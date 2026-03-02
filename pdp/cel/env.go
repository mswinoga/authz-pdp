package cel

import (
	"github.com/google/cel-go/cel"
	pdppb "github.com/marcin/authz-pdp/pdp/gen/pdp"
)

// buildEnv constructs the shared CEL environment with proto types registered,
// all input variables declared, and PDP macros registered. Called once at startup.
func buildEnv() (*cel.Env, error) {
	return cel.NewEnv(
		// Register proto message descriptors so field names are validated
		// at policy compile time rather than at request evaluation time.
		cel.Types(
			new(pdppb.Peer),
			new(pdppb.Operation),
		),

		// peer is nullable: pass types.NullValue when no peer cert is present.
		cel.Variable("peer", cel.ObjectType("pdp.Peer")),

		// jwt is nullable: pass types.NullValue when jwt_authn metadata is absent.
		// Declared as dyn so that jwt == null works; google.protobuf.Struct is a
		// CEL Well-Known Type that maps to map(string,dyn), which has no == null overload.
		cel.Variable("jwt", cel.DynType),

		// operation is never null; all string fields are "" when not configured.
		cel.Variable("operation", cel.ObjectType("pdp.Operation")),

		// resource and action are the raw HTTP request path and method.
		// Policy files should use any_path() and any_verb() rather than
		// referencing these variables directly.
		cel.Variable("resource", cel.StringType),
		cel.Variable("action", cel.StringType),

		// PDP macros: stable policy interface decoupled from the input model.
		// Policy files should use macros rather than referencing jwt/peer/operation directly.
		cel.Macros(pdpMacros()...),
	)
}
