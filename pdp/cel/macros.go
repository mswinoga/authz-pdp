package cel

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/parser"
)

// pdpMacros returns all custom PDP macros to be registered in the CEL environment.
//
// These macros form a stable policy interface that decouples policy expressions from
// the underlying input model. Policy files should use macros rather than referencing
// jwt, peer, or operation fields directly, so that model changes only require
// updating macro implementations, not policy files.
//
// All scope macros guard against jwt == null; scope checks on a null jwt return false
// without error. any_peer guards against peer == null similarly.
func pdpMacros() []cel.Macro {
	return []cel.Macro{
		// scope("s") — jwt carries this single scope
		cel.GlobalMacro("scope", 1, scopeMacro),

		// any_scope("s1", "s2", ...) — jwt carries at least one of the listed scopes
		cel.GlobalVarArgMacro("any_scope", anyScopeMacro),

		// all_scopes("s1", "s2", ...) — jwt carries every listed scope
		cel.GlobalVarArgMacro("all_scopes", allScopesMacro),

		// any_peer("p1", "p2", ...) — peer.cn matches one of the listed values
		cel.GlobalVarArgMacro("any_peer", anyPeerMacro),

		// any_operation("op1", "op2", ...) — operation.id matches one of the listed values
		cel.GlobalVarArgMacro("any_operation", anyOperationMacro),

		// any_path("/prefix1", "/prefix2", ...) — operation.path starts with one of the listed prefixes
		cel.GlobalVarArgMacro("any_path", anyPathMacro),

		// any_verb("GET", "POST", ...) — operation.method matches one of the listed HTTP verbs
		cel.GlobalVarArgMacro("any_verb", anyVerbMacro),
	}
}

// scope("s") → jwt != null && "s" in jwt["scopes"]
func scopeMacro(eh cel.MacroExprFactory, _ ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
	return jwtHasScope(eh, args[0]), nil
}

// any_scope("s1", ...) → jwt != null && ["s1",...].exists(__s__, __s__ in jwt["scopes"])
func anyScopeMacro(eh cel.MacroExprFactory, _ ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
	if len(args) == 0 {
		return eh.NewLiteral(types.False), nil
	}
	if len(args) == 1 {
		return jwtHasScope(eh, args[0]), nil
	}
	pred := eh.NewCall(operators.In, eh.NewIdent("__s__"), jwtScopes(eh))
	comp := existsComp(eh, eh.NewList(args...), "__s__", pred)
	return eh.NewCall(operators.LogicalAnd, jwtNotNull(eh), comp), nil
}

// all_scopes("s1", ...) → jwt != null && ["s1",...].all(__s__, __s__ in jwt["scopes"])
func allScopesMacro(eh cel.MacroExprFactory, _ ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
	if len(args) == 0 {
		return jwtNotNull(eh), nil
	}
	if len(args) == 1 {
		return jwtHasScope(eh, args[0]), nil
	}
	pred := eh.NewCall(operators.In, eh.NewIdent("__s__"), jwtScopes(eh))
	comp := allComp(eh, eh.NewList(args...), "__s__", pred)
	return eh.NewCall(operators.LogicalAnd, jwtNotNull(eh), comp), nil
}

// any_peer("p1", ...) → peer != null && peer.cn in ["p1",...]
func anyPeerMacro(eh cel.MacroExprFactory, _ ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
	if len(args) == 0 {
		return peerNotNull(eh), nil
	}
	peerCN := eh.NewSelect(eh.NewIdent("peer"), "cn")
	return eh.NewCall(operators.LogicalAnd,
		peerNotNull(eh),
		eh.NewCall(operators.In, peerCN, eh.NewList(args...)),
	), nil
}

// any_operation("op1", ...) → operation.id in ["op1",...]
func anyOperationMacro(eh cel.MacroExprFactory, _ ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
	if len(args) == 0 {
		return eh.NewLiteral(types.False), nil
	}
	opID := eh.NewSelect(eh.NewIdent("operation"), "id")
	return eh.NewCall(operators.In, opID, eh.NewList(args...)), nil
}

// any_path("/p1", ...) → ["/p1",...].exists(__p__, resource.startsWith(__p__))
func anyPathMacro(eh cel.MacroExprFactory, _ ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
	if len(args) == 0 {
		return eh.NewLiteral(types.False), nil
	}
	pred := eh.NewMemberCall("startsWith", eh.NewIdent("resource"), eh.NewIdent("__p__"))
	return existsComp(eh, eh.NewList(args...), "__p__", pred), nil
}

// any_verb("GET", ...) → action in ["GET",...]
func anyVerbMacro(eh cel.MacroExprFactory, _ ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
	if len(args) == 0 {
		return eh.NewLiteral(types.False), nil
	}
	return eh.NewCall(operators.In, eh.NewIdent("action"), eh.NewList(args...)), nil
}

// --- helpers ----------------------------------------------------------------

func jwtNotNull(eh cel.MacroExprFactory) ast.Expr {
	return eh.NewCall(operators.NotEquals, eh.NewIdent("jwt"), eh.NewLiteral(types.NullValue))
}

func peerNotNull(eh cel.MacroExprFactory) ast.Expr {
	return eh.NewCall(operators.NotEquals, eh.NewIdent("peer"), eh.NewLiteral(types.NullValue))
}

func jwtScopes(eh cel.MacroExprFactory) ast.Expr {
	return eh.NewCall(operators.Index, eh.NewIdent("jwt"), eh.NewLiteral(types.String("scopes")))
}

// jwtHasScope expands to: jwt != null && s in jwt["scopes"]
func jwtHasScope(eh cel.MacroExprFactory, s ast.Expr) ast.Expr {
	return eh.NewCall(operators.LogicalAnd,
		jwtNotNull(eh),
		eh.NewCall(operators.In, s, jwtScopes(eh)),
	)
}

// existsComp builds a comprehension equivalent to iterRange.exists(iterVar, pred).
func existsComp(eh cel.MacroExprFactory, iterRange ast.Expr, iterVar string, pred ast.Expr) ast.Expr {
	return eh.NewComprehension(
		iterRange,
		iterVar,
		parser.AccumulatorName,
		eh.NewLiteral(types.False),
		eh.NewCall(operators.NotStrictlyFalse, eh.NewCall(operators.LogicalNot, eh.NewAccuIdent())),
		eh.NewCall(operators.LogicalOr, eh.NewAccuIdent(), pred),
		eh.NewAccuIdent(),
	)
}

// allComp builds a comprehension equivalent to iterRange.all(iterVar, pred).
func allComp(eh cel.MacroExprFactory, iterRange ast.Expr, iterVar string, pred ast.Expr) ast.Expr {
	return eh.NewComprehension(
		iterRange,
		iterVar,
		parser.AccumulatorName,
		eh.NewLiteral(types.True),
		eh.NewCall(operators.NotStrictlyFalse, eh.NewAccuIdent()),
		eh.NewCall(operators.LogicalAnd, eh.NewAccuIdent(), pred),
		eh.NewAccuIdent(),
	)
}
