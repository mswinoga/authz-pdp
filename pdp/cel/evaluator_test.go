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
	somePeer = &pdppb.Peer{Cn: "svc-a", Auid: "ap12345", Uri: "spiffe://prod/svc-a"}
	someJWT  = makeJWT(map[string]any{"sub": "alice", "scopes": []any{"viewer"}})
	adminJWT = makeJWT(map[string]any{"sub": "admin", "scopes": []any{"order:admin"}})
	someOp   = &pdppb.Operation{Id: "Order_Get", Api: "orders", Version: "v1"}
	emptyOp  = &pdppb.Operation{}
)

func ctx(peer *pdppb.Peer, jwt *structpb.Struct, op *pdppb.Operation, resource, action string) EvalContext {
	return EvalContext{Peer: peer, Jwt: jwt, Operation: op, Resource: resource, Action: action}
}

func TestEvaluate(t *testing.T) {
	const basePolicy = `
version: 1
rules:
  - id: deny-no-identity
    deny: peer == null || jwt == null
  - id: allow-admin
    allow: any_scope("order:admin")
  - id: allow-service-readonly
    allow: any_peer("svc-a") &&
           peer.auid == "ap12345" &&
           any_operation("Order_Get", "Order_List")
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
			name:      "null peer → deny via deny-no-identity",
			ctx:       ctx(nil, someJWT, someOp, "/v1/orders", "GET"),
			wantAllow: false,
		},
		{
			name:      "null jwt → deny via deny-no-identity",
			ctx:       ctx(somePeer, nil, someOp, "/v1/orders", "GET"),
			wantAllow: false,
		},
		{
			name:      "admin JWT → allow via allow-admin",
			ctx:       ctx(somePeer, adminJWT, someOp, "/v1/orders", "GET"),
			wantAllow: true,
		},
		{
			name:      "matching service + operation → allow",
			ctx:       ctx(somePeer, someJWT, someOp, "/v1/orders", "GET"),
			wantAllow: true,
		},
		{
			name:      "wrong operation id → deny via deny-all",
			ctx:       ctx(somePeer, someJWT, &pdppb.Operation{Id: "Order_Delete"}, "/v1/orders/1", "DELETE"),
			wantAllow: false,
		},
		{
			name:      "wrong CN → deny via deny-all",
			ctx:       ctx(&pdppb.Peer{Cn: "svc-b", Auid: "ap12345"}, someJWT, someOp, "/v1/orders", "GET"),
			wantAllow: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := ev.Evaluate(tc.ctx, slog.Default())
			if got != tc.wantAllow {
				t.Errorf("Evaluate() = %v, want %v", got, tc.wantAllow)
			}
		})
	}
}

func TestEvaluateNullGuardError(t *testing.T) {
	const p = `
version: 1
rules:
  - id: unguarded-access
    allow: peer.cn == "svc-a"
`
	ev := newEvaluator(t, p)
	if got, _ := ev.Evaluate(ctx(nil, someJWT, emptyOp, "/", "GET"), slog.Default()); got {
		t.Error("expected deny on CEL error from unguarded null access")
	}
}

func TestEvaluateNoMatch(t *testing.T) {
	const p = `
version: 1
rules:
  - id: allow-only-post
    allow: any_verb("POST")
`
	ev := newEvaluator(t, p)
	if got, _ := ev.Evaluate(ctx(somePeer, someJWT, emptyOp, "/", "GET"), slog.Default()); got {
		t.Error("expected deny when no rule matches")
	}
}

func TestEvaluateErrorStopsEvaluation(t *testing.T) {
	const p = `
version: 1
rules:
  - id: error-rule
    deny: peer.cn == "bad"
  - id: allow-all
    allow: "true"
`
	ev := newEvaluator(t, p)
	if got, _ := ev.Evaluate(ctx(nil, someJWT, emptyOp, "/", "GET"), slog.Default()); got {
		t.Error("expected deny: error in first rule must stop evaluation")
	}
}

func TestEvaluateHasMacro(t *testing.T) {
	const p = `
version: 1
rules:
  - id: allow-if-has-uri
    allow: peer != null && has(peer.uri)
  - id: deny-all
    deny: "true"
`
	ev := newEvaluator(t, p)

	withURI := &pdppb.Peer{Cn: "svc", Uri: "spiffe://prod/svc"}
	withoutURI := &pdppb.Peer{Cn: "svc", Uri: ""}

	if got, _ := ev.Evaluate(ctx(withURI, someJWT, emptyOp, "/", "GET"), slog.Default()); !got {
		t.Error("expected allow when peer has URI")
	}
	if got, _ := ev.Evaluate(ctx(withoutURI, someJWT, emptyOp, "/", "GET"), slog.Default()); got {
		t.Error("expected deny when peer has no URI")
	}
}

func TestNewEvaluatorInvalidExpression(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(path, []byte(`
version: 1
rules:
  - id: bad-expr
    allow: peer.nonexistent_field == "x"
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

// --- macro tests ------------------------------------------------------------


func TestMacroAnyScope(t *testing.T) {
	evMulti := newEvaluator(t, `
version: 1
rules:
  - id: allow-any
    allow: any_scope("adm", "billing")
  - id: deny-all
    deny: "true"
`)
	evSingle := newEvaluator(t, `
version: 1
rules:
  - id: allow-single
    allow: any_scope("adm")
  - id: deny-all
    deny: "true"
`)

	admJWT := makeJWT(map[string]any{"scopes": []any{"adm"}})
	billingJWT := makeJWT(map[string]any{"scopes": []any{"billing"}})
	noneJWT := makeJWT(map[string]any{"scopes": []any{"read"}})

	// multi-arg: any match
	if got, _ := evMulti.Evaluate(ctx(somePeer, admJWT, emptyOp, "/", "GET"), slog.Default()); !got {
		t.Error("expected allow: jwt has adm scope")
	}
	if got, _ := evMulti.Evaluate(ctx(somePeer, billingJWT, emptyOp, "/", "GET"), slog.Default()); !got {
		t.Error("expected allow: jwt has billing scope")
	}
	if got, _ := evMulti.Evaluate(ctx(somePeer, noneJWT, emptyOp, "/", "GET"), slog.Default()); got {
		t.Error("expected deny: jwt has neither scope")
	}
	if got, _ := evMulti.Evaluate(ctx(somePeer, nil, emptyOp, "/", "GET"), slog.Default()); got {
		t.Error("expected deny: null jwt")
	}

	// single-arg fast path
	if got, _ := evSingle.Evaluate(ctx(somePeer, admJWT, emptyOp, "/", "GET"), slog.Default()); !got {
		t.Error("single-arg: expected allow")
	}
	if got, _ := evSingle.Evaluate(ctx(somePeer, noneJWT, emptyOp, "/", "GET"), slog.Default()); got {
		t.Error("single-arg: expected deny")
	}
}

func TestMacroAllScopes(t *testing.T) {
	evMulti := newEvaluator(t, `
version: 1
rules:
  - id: allow-both
    allow: all_scopes("billing", "read")
  - id: deny-all
    deny: "true"
`)
	evSingle := newEvaluator(t, `
version: 1
rules:
  - id: allow-single
    allow: all_scopes("billing")
  - id: deny-all
    deny: "true"
`)

	bothJWT := makeJWT(map[string]any{"scopes": []any{"billing", "read", "extra"}})
	oneJWT := makeJWT(map[string]any{"scopes": []any{"billing"}})
	noneJWT := makeJWT(map[string]any{"scopes": []any{"other"}})

	// multi-arg: all must match
	if got, _ := evMulti.Evaluate(ctx(somePeer, bothJWT, emptyOp, "/", "GET"), slog.Default()); !got {
		t.Error("expected allow: jwt has both scopes")
	}
	if got, _ := evMulti.Evaluate(ctx(somePeer, oneJWT, emptyOp, "/", "GET"), slog.Default()); got {
		t.Error("expected deny: jwt missing read scope")
	}

	// single-arg fast path
	if got, _ := evSingle.Evaluate(ctx(somePeer, oneJWT, emptyOp, "/", "GET"), slog.Default()); !got {
		t.Error("single-arg: expected allow")
	}
	if got, _ := evSingle.Evaluate(ctx(somePeer, noneJWT, emptyOp, "/", "GET"), slog.Default()); got {
		t.Error("single-arg: expected deny")
	}
}

func TestMacroAnyPeer(t *testing.T) {
	const p = `
version: 1
rules:
  - id: allow-known-services
    allow: any_peer("svc-a", "svc-b")
  - id: deny-all
    deny: "true"
`
	ev := newEvaluator(t, p)

	peerA := &pdppb.Peer{Cn: "svc-a"}
	peerB := &pdppb.Peer{Cn: "svc-b"}
	peerC := &pdppb.Peer{Cn: "svc-c"}

	if got, _ := ev.Evaluate(ctx(peerA, someJWT, emptyOp, "/", "GET"), slog.Default()); !got {
		t.Error("expected allow: svc-a in list")
	}
	if got, _ := ev.Evaluate(ctx(peerB, someJWT, emptyOp, "/", "GET"), slog.Default()); !got {
		t.Error("expected allow: svc-b in list")
	}
	if got, _ := ev.Evaluate(ctx(peerC, someJWT, emptyOp, "/", "GET"), slog.Default()); got {
		t.Error("expected deny: svc-c not in list")
	}
	if got, _ := ev.Evaluate(ctx(nil, someJWT, emptyOp, "/", "GET"), slog.Default()); got {
		t.Error("expected deny: null peer")
	}
}

func TestMacroAnyOperation(t *testing.T) {
	const p = `
version: 1
rules:
  - id: allow-reads
    allow: any_operation("Order_Get", "Order_List")
  - id: deny-all
    deny: "true"
`
	ev := newEvaluator(t, p)

	if got, _ := ev.Evaluate(ctx(somePeer, someJWT, &pdppb.Operation{Id: "Order_Get"}, "/", "GET"), slog.Default()); !got {
		t.Error("expected allow: Order_Get in list")
	}
	if got, _ := ev.Evaluate(ctx(somePeer, someJWT, &pdppb.Operation{Id: "Order_Delete"}, "/", "DELETE"), slog.Default()); got {
		t.Error("expected deny: Order_Delete not in list")
	}
}

func TestMacroAnyPath(t *testing.T) {
	const p = `
version: 1
rules:
  - id: allow-orders-prefix
    allow: any_path("/v1/orders", "/v1/cart")
  - id: deny-all
    deny: "true"
`
	ev := newEvaluator(t, p)

	cases := []struct {
		path string
		want bool
	}{
		{"/v1/orders", true},
		{"/v1/orders/123", true},
		{"/v1/orders/123/items", true},
		{"/v1/cart", true},
		{"/v1/cart/abc", true},
		{"/v1/users", false},
		{"/v2/orders", false},
		{"", false},
	}
	for _, tc := range cases {
		got, _ := ev.Evaluate(ctx(somePeer, someJWT, emptyOp, tc.path, "GET"), slog.Default())
		if got != tc.want {
			t.Errorf("path %q: got %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestMacroAnyVerb(t *testing.T) {
	const p = `
version: 1
rules:
  - id: allow-reads
    allow: any_verb("GET", "HEAD")
  - id: deny-all
    deny: "true"
`
	ev := newEvaluator(t, p)

	for _, verb := range []string{"GET", "HEAD"} {
		if got, _ := ev.Evaluate(ctx(somePeer, someJWT, emptyOp, "/", verb), slog.Default()); !got {
			t.Errorf("expected allow for verb %s", verb)
		}
	}
	for _, verb := range []string{"POST", "DELETE", "PATCH"} {
		if got, _ := ev.Evaluate(ctx(somePeer, someJWT, emptyOp, "/", verb), slog.Default()); got {
			t.Errorf("expected deny for verb %s", verb)
		}
	}
}

func TestMacroComposition(t *testing.T) {
	const p = `
version: 1
rules:
  - id: deny-no-identity
    deny: peer == null || jwt == null
  - id: allow-svc-a-orders-read
    allow: any_peer("svc-a") &&
           any_verb("GET", "HEAD") &&
           any_path("/v1/orders") &&
           any_scope("orders:read")
  - id: deny-all
    deny: "true"
`
	ev := newEvaluator(t, p)

	ordersReadJWT := makeJWT(map[string]any{"scopes": []any{"orders:read"}})
	noScopeJWT := makeJWT(map[string]any{"scopes": []any{"other"}})
	peerA := &pdppb.Peer{Cn: "svc-a"}
	peerB := &pdppb.Peer{Cn: "svc-b"}

	cases := []struct {
		name string
		ctx  EvalContext
		want bool
	}{
		{"allow: all match", ctx(peerA, ordersReadJWT, emptyOp, "/v1/orders/1", "GET"), true},
		{"deny: wrong peer", ctx(peerB, ordersReadJWT, emptyOp, "/v1/orders/1", "GET"), false},
		{"deny: wrong verb", ctx(peerA, ordersReadJWT, emptyOp, "/v1/orders/1", "POST"), false},
		{"deny: wrong path", ctx(peerA, ordersReadJWT, emptyOp, "/v1/users/1", "GET"), false},
		{"deny: missing scope", ctx(peerA, noScopeJWT, emptyOp, "/v1/orders/1", "GET"), false},
	}
	for _, tc := range cases {
		got, _ := ev.Evaluate(tc.ctx, slog.Default())
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
