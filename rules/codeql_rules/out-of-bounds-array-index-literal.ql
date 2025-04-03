import cpp

/**
 * @name Out-of-bounds array index
 * @description Finds local array accesses with a constant index >= array size.
 * @kind problem
 * @id cpp/oob-constant-index
 * @problem.severity warning
 */
from ArrayType at, VariableAccess va, LocalVarDecl lvd, IntegerLiteral ilSize, IntegerLiteral ilIndex
where
  -- The local variable is an array type with a fixed size.
  lvd.getType() = at and
  at.getDimension() = ilSize and
  va.getTarget() = lvd and
  -- The array is accessed with a constant integer subscript.
  va.getArrayIndex() = ilIndex and
  -- Index >= size
  ilIndex.getValue().toInt() >= ilSize.getValue().toInt()
select va,
  "Potential out-of-bounds array index: " + ilIndex.getValue().toString() + 
  " >= declared size " + ilSize.getValue().toString()