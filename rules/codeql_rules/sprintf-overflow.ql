import cpp

/**
 * @name sprintf stack-buffer overflow vulnerability
 * @description Finds sprintf calls where the destination is a fixed-size local array.
 * @kind path-problem
 * @id cpp/sprintf-stack-buffer-overflow
 * @problem.severity warning
 */
from CallExpr call, LocalVarDecl lv, VariableAccess va
where
  call.getCallee().getName() = "sprintf" and
  call.getArgument(0) = va and
  va.getDecl() = lv and
  lv.getType() instanceof ArrayType
select call, "Potential stack buffer overflow: sprintf writing into a fixed-size stack buffer."
