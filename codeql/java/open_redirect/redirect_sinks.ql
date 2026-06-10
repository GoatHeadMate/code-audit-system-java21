/**
 * 查找所有重定向写入点（不区分来源），用于人工核查。
 */
import java

from MethodCall ma
where
  ma.getMethod().getDeclaringType().getASupertype*()
      .hasQualifiedName("javax.servlet.http", "HttpServletResponse")
  and ma.getMethod().hasName("sendRedirect")
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.getArgument(0).toString()                 as redirect_target
