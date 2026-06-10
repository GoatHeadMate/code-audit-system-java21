/**
 * 查找所有 HTTP 响应头写入点，用于人工判断是否接收用户输入。
 */
import java

from MethodCall ma
where
  ma.getMethod().getDeclaringType().getASupertype*()
      .hasQualifiedName("javax.servlet.http", "HttpServletResponse")
  and ma.getMethod().getName() in ["addHeader", "setHeader", "sendRedirect"]
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.getMethod().getName()                     as method,
  ma.getArgument(0).toString()                 as header_name
