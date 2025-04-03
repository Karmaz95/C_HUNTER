import cpp

/**
 * @name Sequential hex data copy buffer overflow vulnerability
 * @description Finds loops that sequentially copy hex data from an input into a fixed-size buffer without verifying destination bounds.
 * @kind path-problem
 * @id cpp/sequential-hex-copy-buffer-overflow
 * @problem.severity error
 */
from WhileStmt ws, IfStmt ifs, CallExpr call, UnaryOperator u
where
  // Detect an infinite loop (while(1))
  ws.getCondition().toString() = "1" and
  // Look for an if-statement within the loop that checks strnlen on an input buffer.
  ifs.getEnclosingStmt() = ws and
  ifs.getCondition().toString().matches(".*strnlen\\s*\\(.*\\).*") and
  // Identify a pointer dereference with post-increment within the loop body.
  exists(u | u.getOperator() = "++" and ws.getBody().toString().matches(".*\\*.*=.*"))
select ws, "Potential buffer overflow: sequential hex data copy without verifying destination bounds."