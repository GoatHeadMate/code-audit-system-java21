/**
 * 查找所有来自 HTTP 请求的用户可控输入（source 点）。
 * 覆盖 Spring MVC @RequestParam / @PathVariable / HttpServletRequest.getParameter 等。
 */
import java
import semmle.code.java.dataflow.FlowSources

from RemoteFlowSource source
select
  source,
  source.getLocation().getFile().getRelativePath() as file,
  source.getLocation().getStartLine()              as line,
  source.toString()                                as source_expr
