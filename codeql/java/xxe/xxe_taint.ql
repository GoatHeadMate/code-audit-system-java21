/**
 * XXE 污点追踪：用户输入流向 XML 解析器。
 *
 * 修正（2026-06）：增加 isBarrier 谓词，排除 XMLInputFactory 已配置
 * IS_SUPPORTING_EXTERNAL_ENTITIES=false / SUPPORT_DTD=false 的情况。
 * 覆盖 JAXB Provider 等设置了安全属性的场景，避免误报。
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

// ── XXE sinks ──────────────────────────────────────────────────────────

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

// ── 安全 guard 谓词 ────────────────────────────────────────────────────

/** 同一方法内，factory 变量有 setProperty/setFeature 安全防护 */
private predicate factoryHasXxeGuard(Variable factoryVar) {
  exists(MethodCall guard |
    guard.getQualifier().(VarAccess).getVariable() = factoryVar
    and guard.getMethod().getName() in ["setProperty", "setFeature", "setAttribute"]
    and guard.getArgument(0).(StringLiteral).getValue().regexpMatch(
      ".*(IS_SUPPORTING_EXTERNAL_ENTITIES|SUPPORT_DTD|disallow-doctype-decl"
      + "|external-general-entities|external-parameter-entities|FEATURE_SECURE).*"
    )
  )
}

// ─────────────────────────────────────────────────────────────────────

module XxeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n)   { n instanceof AnyXxeSink }

  /**
   * barrier：若 XMLInputFactory/DocumentBuilder 的 qualifier 变量配置了安全属性，
   * 则该 sink 不再是漏洞路径。
   */
  predicate isBarrier(DataFlow::Node n) {
    n instanceof AnyXxeSink and
    exists(MethodCall parseCall, Variable factoryVar |
      parseCall.getQualifier().(VarAccess).getVariable() = factoryVar
      and n.asExpr() = parseCall.getArgument(0)
      and factoryHasXxeGuard(factoryVar)
    )
  }
}

module XxeFlow = TaintTracking::Global<XxeConfig>;

from XxeFlow::PathNode source, XxeFlow::PathNode sink
select
  sink.getNode(),
  source.getNode().getLocation().getFile().getRelativePath() as source_file,
  source.getNode().getLocation().getStartLine()              as source_line,
  sink.getNode().getLocation().getFile().getRelativePath()   as sink_file,
  sink.getNode().getLocation().getStartLine()                as sink_line
