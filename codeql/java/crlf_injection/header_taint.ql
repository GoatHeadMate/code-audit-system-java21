/**
 * CRLF 注入污点追踪：用户输入流向 HTTP 响应头设置方法。
 * 若输入未过滤 \r\n，攻击者可注入额外响应头或分割 HTTP 响应。
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

/** HTTP 响应头写入 sink */
class ResponseHeaderSink extends DataFlow::Node {
  ResponseHeaderSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("javax.servlet.http", "HttpServletResponse")
      and ma.getMethod().getName() in ["addHeader", "setHeader", "sendRedirect", "addCookie"]
      and this.asExpr() = ma.getAnArgument()
    )
    or
    // Spring HttpHeaders.set/add
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("org.springframework.http", "HttpHeaders")
      and ma.getMethod().getName() in ["set", "add"]
      and this.asExpr() = ma.getAnArgument()
    )
  }
}

module CrlfConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n)   { n instanceof ResponseHeaderSink }
}

module CrlfFlow = TaintTracking::Global<CrlfConfig>;

from CrlfFlow::PathNode source, CrlfFlow::PathNode sink
select
  sink.getNode(),
  source.getNode().getLocation().getFile().getRelativePath() as source_file,
  source.getNode().getLocation().getStartLine()              as source_line,
  sink.getNode().getLocation().getFile().getRelativePath()   as sink_file,
  sink.getNode().getLocation().getStartLine()                as sink_line
