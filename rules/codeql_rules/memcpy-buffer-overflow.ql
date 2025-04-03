import cpp

/**
 * @name memcpy stack-buffer overflow vulnerability
 * @description Finds `memcpy` calls where the destination is a fixed-size stack buffer, but no bounds checking is performed.
 * @kind path-problem
 * @id cpp/memcpy-buffer-overflow
 * @problem.severity error
 */
from CallExpr call, LocalVarDecl lv, VariableAccess va
where
  call.getCallee().getName() = "memcpy" and
  call.getArgument(0) = va and
  va.getDecl() = lv and
  lv.getType() instanceof ArrayType and
  not exists(BinaryExpr cond | 
    cond.getOperator() = "<" and 
    cond.getLeftOperand() = call.getArgument(2))
select call, "Potential stack buffer overflow: `memcpy` copies data into a fixed-size stack buffer without bounds checking."