package cel

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	pdppb "github.com/marcin/authz-pdp/pdp/gen/pdp"
	"github.com/marcin/authz-pdp/pdp/policy"
	"google.golang.org/protobuf/types/known/structpb"
)

// newEvaluator compiles an inline policy YAML. Fails the test on any error.
func newEvaluator(t *testing.T, yaml string) *Evaluator {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatalf("write temp policy: %v", err)
	}
	p, err := policy.LoadFile(path, slog.Default())
	if err != nil {
		t.Fatalf("policy.LoadFile: %v", err)
	}
	ev, err := NewEvaluator(p, slog.Default())
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}
	return ev
}

func makeJWT(claims map[string]any) *structpb.Struct {
	s, err := structpb.NewStruct(claims)
	if err != nil {
		panic(err)
	}
	return s
}

var (
	someActor = &pdppb.Actor{Cn: "svc-a", Auid: "ap12345", Uri: "spiffe://prod/svc-a"}
	someJWT   = makeJWT(map[string]any{"sub": "alice", "roles": []any{"viewer"}})
	adminJWT  = makeJWT(map[string]any{"sub": "admin", "roles": []any{"order:admin"}})
	someOp    = &pdppb.Operation{Id: "Order_Get", Scope: "orders", Version: "v1"}
	emptyOp   = &pdppb.Operation{}
)

func subjectWith(jwt *structpb.Struct) *pdppb.Subject { return &pdppb.Subject{Jwt: jwt} }
func subjectNil() *pdppb.Subject                      { return &pdppb.Subject{} }

func TestEvaluate(t *testing.T) {
	const basePolicy = `
version: 1
rules:
  - id: deny-no-identity
    deny: actor == null || !has(subject.jwt)
  - id: allow-admin
    allow: has(subject.jwt) && "order:admin" in subject.jwt["roles"]
  - id: allow-service-readonly
    allow: actor != null &&
           actor.cn == "svc-a" &&
           actor.auid == "ap12345" &&
           operation.id in ["Order_Get", "Order_List"]
  - id: deny-all
    deny: "true"
`

	ev := newEvaluator(t, basePolicy)

	tests := []struct {
		name      string
		ctx       EvalContext
		wantAllow bool
	}{
		{
			name:      "null actor → deny via deny-no-identity",
			ctx:       EvalContext{Actor: nil, Subject: subjectWith(someJWT), Operation: someOp, Resource: "/orders", Action: "GET"},
			wantAllow: false,
		},
		{
			name:      "null jwt → deny via deny-no-identity",
			ctx:       EvalContext{Actor: someActor, Subject: subjectNil(), Operation: someOp, Resource: "/orders", Action: "GET"},
			wantAllow: false,
		},
		{
			name:      "admin JWT → allow via allow-admin",
			ctx:       EvalContext{Actor: someActor, Subject: subjectWith(adminJWT), Operation: someOp, Resource: "/orders", Action: "GET"},
			wantAllow: true,
		},
		{
			name:      "matching service + operation → allow",
			ctx:       EvalContext{Actor: someActor, Subject: subjectWith(someJWT), Operation: someOp, Resource: "/orders", Action: "GET"},
			wantAllow: true,
		},
		{
			name:      "wrong operation id → deny via deny-all",
			ctx:       EvalContext{Actor: someActor, Subject: subjectWith(someJWT), Operation: &pdppb.Operation{Id: "Order_Delete"}, Resource: "/orders", Action: "DELETE"},
			wantAllow: false,
		},
		{
			name:      "wrong CN → deny via deny-all",
			ctx:       EvalContext{Actor: &pdppb.Actor{Cn: "svc-b", Auid: "ap12345"}, Subject: subjectWith(someJWT), Operation: someOp, Resource: "/orders", Action: "GET"},
			wantAllow: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := ev.Evaluate(tc.ctx)
			if got != tc.wantAllow {
				t.Errorf("Evaluate() = %v, want %v", got, tc.wantAllow)
			}
		})
	}
}

func TestEvaluateNullGuardError(t *testing.T) {
	// A rule that accesses actor.cn without a null guard — when actor is nil,
	// this produces a CEL runtime error → immediate deny.
	const p = `
version: 1
rules:
  - id: unguarded-access
    allow: actor.cn == "svc-a"
`
	ev := newEvaluator(t, p)
	ctx := EvalContext{
		Actor:     nil, // null actor
		Subject:   subjectWith(someJWT),
		Operation: emptyOp,
		Resource:  "/",
		Action:    "GET",
	}
	if got, _ := ev.Evaluate(ctx); got {
		t.Error("expected deny on CEL error from unguarded null access")
	}
}

func TestEvaluateNoMatch(t *testing.T) {
	// A policy where no rule matches → default deny.
	const p = `
version: 1
rules:
  - id: allow-only-post
    allow: action == "POST"
`
	ev := newEvaluator(t, p)
	ctx := EvalContext{
		Actor:     someActor,
		Subject:   subjectWith(someJWT),
		Operation: emptyOp,
		Resource:  "/",
		Action:    "GET",
	}
	if got, _ := ev.Evaluate(ctx); got {
		t.Error("expected deny when no rule matches")
	}
}

func TestEvaluateErrorStopsEvaluation(t *testing.T) {
	// Rule 1 errors (unguarded null access), rule 2 would allow.
	// Error in rule 1 must deny immediately — rule 2 must not be reached.
	const p = `
version: 1
rules:
  - id: error-rule
    deny: actor.cn == "bad"
  - id: allow-all
    allow: "true"
`
	ev := newEvaluator(t, p)
	ctx := EvalContext{
		Actor:     nil, // causes error in rule 1
		Subject:   subjectWith(someJWT),
		Operation: emptyOp,
		Resource:  "/",
		Action:    "GET",
	}
	if got, _ := ev.Evaluate(ctx); got {
		t.Error("expected deny: error in first rule must stop evaluation")
	}
}

func TestEvaluateHasMacro(t *testing.T) {
	// has() on a proto field returns true iff the value is non-zero.
	const p = `
version: 1
rules:
  - id: allow-if-has-uri
    allow: actor != null && has(actor.uri)
  - id: deny-all
    deny: "true"
`
	ev := newEvaluator(t, p)

	withURI := &pdppb.Actor{Cn: "svc", Uri: "spiffe://prod/svc"}
	withoutURI := &pdppb.Actor{Cn: "svc", Uri: ""}

	if got, _ := ev.Evaluate(EvalContext{Actor: withURI, Subject: subjectWith(someJWT), Operation: emptyOp, Resource: "/", Action: "GET"}); !got {
		t.Error("expected allow when actor has URI")
	}
	if got, _ := ev.Evaluate(EvalContext{Actor: withoutURI, Subject: subjectWith(someJWT), Operation: emptyOp, Resource: "/", Action: "GET"}); got {
		t.Error("expected deny when actor has no URI")
	}
}

func TestNewEvaluatorInvalidExpression(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(path, []byte(`
version: 1
rules:
  - id: bad-expr
    allow: actor.nonexistent_field == "x"
`), 0600)
	p, err := policy.LoadFile(path, slog.Default())
	if err != nil {
		t.Fatalf("policy.LoadFile: %v", err)
	}
	_, err = NewEvaluator(p, slog.Default())
	if err == nil {
		t.Error("expected compile error for unknown field, got nil")
	}
}
