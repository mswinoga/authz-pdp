package cel

import (
	"fmt"
	"log/slog"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	pdppb "github.com/marcin/authz-pdp/pdp/gen/pdp"
	"github.com/marcin/authz-pdp/pdp/policy"
	"google.golang.org/protobuf/types/known/structpb"
)

// EvalContext holds the per-request input variables passed to CEL.
type EvalContext struct {
	Peer      *pdppb.Peer      // nil when no peer cert or cert parse failure
	Jwt       *structpb.Struct // nil when jwt_authn metadata absent
	Operation *pdppb.Operation // never nil; fields are "" when not configured
	Resource  string           // HTTP request path
	Action    string           // HTTP request method
}

// compiledRule pairs a compiled CEL program with its policy decision.
type compiledRule struct {
	id       string
	decision string // "allow" | "deny"
	program  cel.Program
}

// Evaluator holds the compile-once policy programs.
type Evaluator struct {
	rules  []compiledRule
	logger *slog.Logger
}

// NewEvaluator compiles all rules in the policy. Returns an error if any
// rule fails to compile or does not produce a boolean — the service must
// not start with an invalid policy.
func NewEvaluator(p *policy.Policy, logger *slog.Logger) (*Evaluator, error) {
	env, err := buildEnv()
	if err != nil {
		return nil, fmt.Errorf("build CEL env: %w", err)
	}

	rules := make([]compiledRule, 0, len(p.Rules))
	for _, r := range p.Rules {
		decision, expr := r.Decision()

		ast, issues := env.Compile(expr)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("rule %q: compile error: %w", r.ID, issues.Err())
		}
		if ast.OutputType() != cel.BoolType {
			return nil, fmt.Errorf("rule %q: expression must return bool, got %s", r.ID, ast.OutputType())
		}

		prog, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("rule %q: program creation: %w", r.ID, err)
		}

		rules = append(rules, compiledRule{
			id:       r.ID,
			decision: decision,
			program:  prog,
		})
	}

	logger.Info("CEL compiled", "rules", len(rules))
	return &Evaluator{rules: rules, logger: logger}, nil
}

// Evaluate runs the policy against the given context.
// Returns (allow, matchedRule).
// Deny semantics:
//   - CEL evaluation error in any rule → immediate deny, stop
//   - Rule result is not bool → immediate deny, stop
//   - No rule matches → deny
func (e *Evaluator) Evaluate(ctx EvalContext, log *slog.Logger) (allow bool, matchedRule string) {
	activation := buildActivation(ctx)

	for _, rule := range e.rules {
		val, _, err := rule.program.Eval(activation)
		if err != nil {
			// Evaluation error: fail closed.
			log.Warn("CEL eval error", "rule", rule.id, "error", err)
			return false, ""
		}

		b, ok := val.(types.Bool)
		if !ok {
			// Non-boolean result: fail closed.
			return false, ""
		}

		if bool(b) {
			log.Debug("rule matched", "id", rule.id, "decision", rule.decision)
			return rule.decision == "allow", rule.id
		}
		// false: rule did not match, continue to next rule.
		log.Debug("rule", "id", rule.id, "result", bool(b))
	}

	// No rule matched: default deny.
	return false, ""
}

// buildActivation constructs the CEL variable map for one request.
// peer: types.NullValue when no client certificate is present.
// jwt:  types.NullValue when jwt_authn metadata is absent.
func buildActivation(ctx EvalContext) map[string]any {
	var peerVal any = types.NullValue
	if ctx.Peer != nil {
		peerVal = ctx.Peer
	}
	var jwtVal any = types.NullValue
	if ctx.Jwt != nil {
		jwtVal = ctx.Jwt
	}
	return map[string]any{
		"peer":      peerVal,
		"jwt":       jwtVal,
		"operation": ctx.Operation,
		"resource":  ctx.Resource,
		"action":    ctx.Action,
	}
}
