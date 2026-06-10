/**
 * 查找项目中所有 XML 解析调用点（parse / createXMLStreamReader）。
 */
import java
import semmle.code.java.dataflow.DataFlow

// ── XXE sinks（内联，避免相对路径 import）────────────────────────────
private class DocumentBuilderParseSink extends DataFlow::Node {
  DocumentBuilderParseSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("javax.xml.parsers", "DocumentBuilder")
      and ma.getMethod().hasName("parse")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}
private class SaxParserParseSink extends DataFlow::Node {
  SaxParserParseSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("javax.xml.parsers", "SAXParser")
      and ma.getMethod().hasName("parse")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}
private class XmlReaderParseSink extends DataFlow::Node {
  XmlReaderParseSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("org.xml.sax", "XMLReader")
      and ma.getMethod().hasName("parse")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}
private class XmlInputFactorySink extends DataFlow::Node {
  XmlInputFactorySink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("javax.xml.stream", "XMLInputFactory")
      and ma.getMethod().getName().matches("create%")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}
private class AnyXxeSink extends DataFlow::Node {
  AnyXxeSink() {
    this instanceof DocumentBuilderParseSink or
    this instanceof SaxParserParseSink      or
    this instanceof XmlReaderParseSink      or
    this instanceof XmlInputFactorySink
  }
}
// ─────────────────────────────────────────────────────────────────────

from AnyXxeSink sink
select
  sink.getLocation().getFile().getRelativePath() as file,
  sink.getLocation().getStartLine()              as line,
  sink.toString()                                as expression
