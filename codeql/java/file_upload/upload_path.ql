/**
 * 查找文件写入操作的目标路径来源。
 * 覆盖 transferTo / Files.write / FileOutputStream.write 等常见写入方法。
 */
import java

from MethodCall ma
where
  (
    ma.getMethod().hasName("transferTo")
    or
    ma.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files")
    and ma.getMethod().hasName("write")
    or
    ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileOutputStream")
    and ma.getMethod().getName().matches("write%")
  )
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.getMethod().getName()                     as sink_method,
  ma.toString()                                as path_expression
