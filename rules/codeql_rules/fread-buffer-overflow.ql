import cpp

/**
 * @name fread buffer overflow vulnerability
 * @description Detects fread calls where the size argument is user-controlled without bounds checking.
 * @kind path-problem
 * @id cpp/fread-buffer-overflow
 * @problem.severity warning
 */
from CallExpr call, VariableAccess va, FunctionCall fc
where
  call.getCallee().getName() = "fread" and
  call.getArgument(1) = va and
  fc.getTarget().getName() = "read_dword" and
  fc.getArgument(0) = va
select call, "Potential stack buffer overflow: fread called with an unchecked user-controlled size argument."