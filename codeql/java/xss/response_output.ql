/**
 * 查找直接向 HTTP 响应写入内容的代码。
 * 覆盖 HttpServletResponse.getWriter().print/write/println /
 * OutputStream.write 以及 @ResponseBody 标注的直接返回字符串的方法。
 */
import java

from MethodCall ma
where
  ma.getMethod().getDeclaringType().getASupertype*()
    .hasQualifiedName("javax.servlet", "ServletResponse")
  and ma.getMethod().getName().regexpMatch("getWriter|getOutputStream")
  or ma.getMethod().hasQualifiedName("java.io", "PrintWriter", "print")
  or ma.getMethod().hasQualifiedName("java.io", "PrintWriter", "write")
  or ma.getMethod().hasQualifiedName("java.io", "PrintWriter", "println")
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.getEnclosingCallable().getName()          as method_name,
  ma.getMethod().getName()                     as output_type
