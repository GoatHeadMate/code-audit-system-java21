/**
 * Java XSS Sink 库（共享）。
 *
 * 涵盖：PrintWriter / Writer 输出方法、
 * HttpServletResponse.getWriter()、Spring ResponseEntity。
 */
import java
import semmle.code.java.dataflow.DataFlow

/** PrintWriter / Writer.print / println / write / append */
class WriterOutputSink extends DataFlow::Node {
  WriterOutputSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("java.io", "Writer")
      and ma.getMethod().getName() in ["print", "println", "write", "append"]
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** HttpServletResponse.getWriter() / getOutputStream() — 返回值作为响应出口 */
class ServletResponseWriterSink extends DataFlow::Node {
  ServletResponseWriterSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("javax.servlet.http", "HttpServletResponse")
      and ma.getMethod().getName() in ["getWriter", "getOutputStream"]
      and this.asExpr() = ma
    )
  }
}

/** ResponseEntity.ok(body) — Spring MVC 响应体 */
class SpringResponseEntitySink extends DataFlow::Node {
  SpringResponseEntitySink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("org.springframework.http", "ResponseEntity")
      and ma.getMethod().hasName("ok")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** 统一 XSS sink */
class AnyXssSink extends DataFlow::Node {
  AnyXssSink() {
    this instanceof WriterOutputSink or
    this instanceof ServletResponseWriterSink or
    this instanceof SpringResponseEntitySink
  }
}
