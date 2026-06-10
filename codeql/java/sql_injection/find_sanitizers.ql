/**
 * 查找数据流路径上的净化器：PreparedStatement 参数化、输入校验、编码转义等。
 * Agent 用此查询确认某条路径是否已有有效防护。
 */
import java

from MethodCall ma
where
  ma.getMethod().getDeclaringType().getASupertype*()
     .hasQualifiedName("java.sql", "PreparedStatement")
  and ma.getMethod().getName().matches("set%")
select
  ma,
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.getMethod().getName()                     as sanitizer_type,
  "PreparedStatement 参数绑定，路径安全"         as note
