/**
 * XSS 污点追踪：用户输入流向 HTML 响应输出。
 * sink 定义来自共享库 sinks/XssSinks.qll（AnyXssSink 类）。
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

// ── XSS sinks（内联）────────────────────────────────────────────────
private class WriterOutputSink extends DataFlow::Node {
  WriterOutputSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("java.io", "Writer")
      and ma.getMethod().getName() in ["print", "println", "write", "append"]
      and this.asExpr() = ma.getArgument(0)
    )
  }
}
private class ServletResponseWriterSink extends DataFlow::Node {
  ServletResponseWriterSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("javax.servlet.http", "HttpServletResponse")
      and ma.getMethod().getName() in ["getWriter", "getOutputStream"]
      and this.asExpr() = ma
    )
  }
}
private class SpringResponseEntitySink extends DataFlow::Node {
  SpringResponseEntitySink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("org.springframework.http", "ResponseEntity")
      and ma.getMethod().hasName("ok")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}
private class AnyXssSink extends DataFlow::Node {
  AnyXssSink() {
    this instanceof WriterOutputSink or
    this instanceof ServletResponseWriterSink or
    this instanceof SpringResponseEntitySink
  }
}
// ─────────────────────────────────────────────────────────────────────

module XssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n)   { n instanceof AnyXssSink }
}

module XssFlow = TaintTracking::Global<XssConfig>;

from XssFlow::PathNode source, XssFlow::PathNode sink
select
  sink.getNode(),
  source.getNode().getLocation().getFile().getRelativePath() as source_file,
  source.getNode().getLocation().getStartLine()              as source_line,
  sink.getNode().getLocation().getFile().getRelativePath()   as sink_file,
  sink.getNode().getLocation().getStartLine()                as sink_line
