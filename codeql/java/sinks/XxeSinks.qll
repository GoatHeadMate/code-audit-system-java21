/**
 * Java XXE Sink 库（共享）。
 * 涵盖：DocumentBuilder.parse、SAXParser.parse、
 *       XMLReader.parse、XMLInputFactory.createXMLStreamReader 等。
 */
import java
import semmle.code.java.dataflow.DataFlow

/** DocumentBuilder.parse(InputSource/InputStream/...) */
class DocumentBuilderParseSink extends DataFlow::Node {
  DocumentBuilderParseSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("javax.xml.parsers", "DocumentBuilder")
      and ma.getMethod().hasName("parse")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** SAXParser.parse(...) */
class SaxParserParseSink extends DataFlow::Node {
  SaxParserParseSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("javax.xml.parsers", "SAXParser")
      and ma.getMethod().hasName("parse")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** XMLReader.parse(...) */
class XmlReaderParseSink extends DataFlow::Node {
  XmlReaderParseSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("org.xml.sax", "XMLReader")
      and ma.getMethod().hasName("parse")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** XMLInputFactory.createXMLStreamReader(InputStream/Reader) */
class XmlInputFactorySink extends DataFlow::Node {
  XmlInputFactorySink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("javax.xml.stream", "XMLInputFactory")
      and ma.getMethod().getName().matches("create%")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** 统一 XXE sink */
class AnyXxeSink extends DataFlow::Node {
  AnyXxeSink() {
    this instanceof DocumentBuilderParseSink or
    this instanceof SaxParserParseSink      or
    this instanceof XmlReaderParseSink      or
    this instanceof XmlInputFactorySink
  }
}
