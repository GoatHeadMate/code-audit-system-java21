/**
 * SSRF 污点追踪：用户输入流向 URL 构造或 HTTP 请求。
 * sink 定义来自共享库 sinks/SsrfSinks.qll（AnySsrfSink 类）。
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

// ── SSRF sinks（内联）────────────────────────────────────────────────
private class UrlConstructorSink extends DataFlow::Node {
  UrlConstructorSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.net", "URL")
      and this.asExpr() = cie.getArgument(0)
    )
  }
}
private class UriSink extends DataFlow::Node {
  UriSink() {
    exists(MethodCall ma |
      ma.getMethod().hasQualifiedName("java.net", "URI", "create")
      and this.asExpr() = ma.getArgument(0)
    )
    or
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.net", "URI")
      and this.asExpr() = cie.getArgument(0)
    )
  }
}
private class RestTemplateSink extends DataFlow::Node {
  RestTemplateSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("org.springframework.web.client", "RestTemplate")
      and ma.getMethod().getName().regexpMatch("get.*|post.*|put.*|delete.*|exchange|execute")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}
private class WebClientSink extends DataFlow::Node {
  WebClientSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("org.springframework.web.reactive.function.client", "WebClient")
      and ma.getMethod().getName() in ["get", "post", "put", "delete", "method"]
      and this.asExpr() = ma.getArgument(0)
    )
  }
}
private class ApacheHttpClientSink extends DataFlow::Node {
  ApacheHttpClientSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("org.apache.http.client", "HttpClient")
      and ma.getMethod().hasName("execute")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}
private class OkHttpSink extends DataFlow::Node {
  OkHttpSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("okhttp3", "Request$Builder")
      and ma.getMethod().hasName("url")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}
private class AnySsrfSink extends DataFlow::Node {
  AnySsrfSink() {
    this instanceof UrlConstructorSink or
    this instanceof UriSink or
    this instanceof RestTemplateSink or
    this instanceof WebClientSink or
    this instanceof ApacheHttpClientSink or
    this instanceof OkHttpSink
  }
}
// ─────────────────────────────────────────────────────────────────────

module SsrfConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n)   { n instanceof AnySsrfSink }
}

module SsrfFlow = TaintTracking::Global<SsrfConfig>;

from SsrfFlow::PathNode source, SsrfFlow::PathNode sink
select
  sink.getNode(),
  source.getNode().getLocation().getFile().getRelativePath() as source_file,
  source.getNode().getLocation().getStartLine()              as source_line,
  sink.getNode().getLocation().getFile().getRelativePath()   as sink_file,
  sink.getNode().getLocation().getStartLine()                as sink_line
