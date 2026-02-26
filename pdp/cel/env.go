package cel

import (
	"github.com/google/cel-go/cel"
	pdppb "github.com/marcin/authz-pdp/pdp/gen/pdp"
)

// buildEnv constructs the shared CEL environment with proto types registered
// and all input variables declared. Called once at startup.
func buildEnv() (*cel.Env, error) {
	return cel.NewEnv(
		// Register proto message descriptors so field names are validated
		// at policy compile time rather than at request evaluation time.
		cel.Types(
			new(pdppb.Actor),
			new(pdppb.Subject),
			new(pdppb.Operation),
		),

		// actor is nullable: pass types.NullValue when no peer cert is present.
		cel.Variable("actor", cel.ObjectType("pdp.Actor")),

		// subject is never null; subject.jwt (google.protobuf.Struct) may be null.
		cel.Variable("subject", cel.ObjectType("pdp.Subject")),

		// operation is never null; all string fields are "" when not configured.
		cel.Variable("operation", cel.ObjectType("pdp.Operation")),

		// resource and action are always present HTTP request attributes.
		cel.Variable("resource", cel.StringType),
		cel.Variable("action", cel.StringType),
	)
}
