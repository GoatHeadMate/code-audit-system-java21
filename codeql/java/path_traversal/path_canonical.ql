/**
 * 查找路径规范化方法的调用。
 * File.getCanonicalPath() / Path.toRealPath() / Path.normalize()
 * 可解析 ../ 等相对路径，是路径遍历的防护措施之一。
 * 有调用则 has_validation = true。
 */
import java

from MethodCall ma
where
  ma.getMethod().hasQualifiedName("java.io", "File", "getCanonicalPath")
  or ma.getMethod().hasQualifiedName("java.nio.file", "Path", "toRealPath")
  or ma.getMethod().hasQualifiedName("java.nio.file", "Path", "normalize")
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.getEnclosingCallable().getName()          as method_name,
  true                                         as has_validation
