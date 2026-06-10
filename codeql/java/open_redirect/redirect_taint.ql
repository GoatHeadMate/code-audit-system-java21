/**
 * 开放重定向污点追踪：用户输入流向 HTTP 重定向目标。
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

/** HTTP 重定向 sink */
class RedirectSink extends DataFlow::Node {
  RedirectSink() {
    // response.sendRedirect(url)
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("javax.servlet.http", "HttpServletResponse")
      and ma.getMethod().hasName("sendRedirect")
      and this.asExpr() = ma.getArgument(0)
    )
    or
    // Spring: return "redirect:" + url
    exists(ReturnStmt rs |
      rs.getResult() instanceof AddExpr and
      rs.getResult().(AddExpr).getLeftOperand().(StringLiteral).getValue() = "redirect:"
      and this.asExpr() = rs.getResult().(AddExpr).getRightOperand()
    )
    or
    // Spring RedirectView constructor
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("org.springframework.web.servlet.view", "RedirectView")
      and this.asExpr() = cie.getArgument(0)
    )
  }
}

module RedirectConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n)   { n instanceof RedirectSink }
}

module RedirectFlow = TaintTracking::Global<RedirectConfig>;

from RedirectFlow::PathNode source, RedirectFlow::PathNode sink
select
  sink.getNode(),
  source.getNode().getLocation().getFile().getRelativePath() as source_file,
  source.getNode().getLocation().getStartLine()              as source_line,
  sink.getNode().getLocation().getFile().getRelativePath()   as sink_file,
  sink.getNode().getLocation().getStartLine()                as sink_line
