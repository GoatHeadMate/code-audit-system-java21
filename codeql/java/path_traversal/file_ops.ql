/**
 * 查找基于字符串构造的文件路径操作。
 * 覆盖 new File(path) / new FileInputStream(path) / new FileOutputStream(path)。
 */
import java

from ClassInstanceExpr ce
where
  ce.getConstructor().getDeclaringType().getASupertype*()
    .hasQualifiedName("java.io", "File")
  or ce.getConstructor().getDeclaringType().getASupertype*()
    .hasQualifiedName("java.io", "FileInputStream")
  or ce.getConstructor().getDeclaringType().getASupertype*()
    .hasQualifiedName("java.io", "FileOutputStream")
select
  ce.getLocation().getFile().getRelativePath() as file,
  ce.getLocation().getStartLine()              as line,
  ce.getConstructor().getDeclaringType().getName() as operation_type,
  ce.getArgument(0).toString()                 as path_source
