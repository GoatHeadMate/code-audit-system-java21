/**
 * Java SSRF Sink 库（共享）。
 *
 * 涵盖：java.net.URL、java.net.URI、HttpURLConnection、
 * Apache HttpClient、Spring RestTemplate / WebClient、OkHttp。
 */
import java
import semmle.code.java.dataflow.DataFlow

// ─── URL / URI 构造 ──────────────────────────────────────────────────────────

/** new URL(urlString) — URL 构造器第一个参数 */
class UrlConstructorSink extends DataFlow::Node {
  UrlConstructorSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.net", "URL")
      and this.asExpr() = cie.getArgument(0)
    )
  }
}

/** URI.create(str) / new URI(str) */
class UriSink extends DataFlow::Node {
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

// ─── HTTP 客户端 ─────────────────────────────────────────────────────────────

/** Spring RestTemplate.get* / post* / exchange / execute */
class RestTemplateSink extends DataFlow::Node {
  RestTemplateSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("org.springframework.web.client", "RestTemplate")
      and ma.getMethod().getName().regexpMatch("get.*|post.*|put.*|delete.*|exchange|execute")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** Spring WebClient URL 参数 */
class WebClientSink extends DataFlow::Node {
  WebClientSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("org.springframework.web.reactive.function.client", "WebClient")
      and ma.getMethod().getName() in ["get", "post", "put", "delete", "method"]
      // uri() 方法接收 URL，作为 builder 链式调用
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** Apache HttpClient execute(request) 中的 URI 参数 */
class ApacheHttpClientSink extends DataFlow::Node {
  ApacheHttpClientSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("org.apache.http.client", "HttpClient")
      and ma.getMethod().hasName("execute")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** OkHttp Request.Builder.url(urlString) */
class OkHttpSink extends DataFlow::Node {
  OkHttpSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("okhttp3", "Request$Builder")
      and ma.getMethod().hasName("url")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** 统一 SSRF sink */
class AnySsrfSink extends DataFlow::Node {
  AnySsrfSink() {
    this instanceof UrlConstructorSink or
    this instanceof UriSink or
    this instanceof RestTemplateSink or
    this instanceof WebClientSink or
    this instanceof ApacheHttpClientSink or
    this instanceof OkHttpSink
  }
}
