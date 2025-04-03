import cpp

/**
 * @name Unchecked memmove size from user-controlled buffer
 * @description Detects calls to memmove where the size argument is taken directly from an untrusted parameter.
 * @kind path-problem
 * @id cpp/memmove-size-untrusted
 * @problem.severity warning
 */
from CallExpr call, Expr sizeArg, FunctionInputParameter param
where
  call.getCallee().getName() = "memmove" and
  call.getArgument(2) = sizeArg and
  // Heuristic: match if sizeArg is derived from a function parameter 
  // that looks like a pointer (could be named something like struct_in).
  sizeArg.(VariableAccess).getTarget() = param and
  param.getType() instanceof PointerType
select call, "Potential memory corruption: memmove size argument comes from untrusted parameter."