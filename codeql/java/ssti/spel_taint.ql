/**
 * SSTI 污点追踪：用户输入流向 SpEL 表达式解析器。
 * 覆盖 ExpressionParser.parseExpression(userInput) 场景。
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

/** SpEL ExpressionParser.parseExpression(expr) sink */
class SpelParseSink extends DataFlow::Node {
  SpelParseSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("org.springframework.expression", "ExpressionParser")
      and ma.getMethod().hasName("parseExpression")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

module SpelConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n)   { n instanceof SpelParseSink }
}

module SpelFlow = TaintTracking::Global<SpelConfig>;

from SpelFlow::PathNode source, SpelFlow::PathNode sink
select
  sink.getNode(),
  source.getNode().getLocation().getFile().getRelativePath() as source_file,
  source.getNode().getLocation().getStartLine()              as source_line,
  sink.getNode().getLocation().getFile().getRelativePath()   as sink_file,
  sink.getNode().getLocation().getStartLine()                as sink_line
