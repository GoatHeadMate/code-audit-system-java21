/**
 * Log4Shell (CVE-2021-44228) 污点追踪：
 * 用户可控输入流向 Log4j Logger 的任意日志方法。
 *
 * Log4j 2.x（< 2.15.0）会对日志消息中的 ${jndi:ldap://...} 进行解析和外部请求，
 * 攻击者通过注入此字符串可触发 JNDI 注入实现 RCE。
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

/** Log4j Logger 日志方法调用 sink */
private class Log4jLogSink extends DataFlow::Node {
  Log4jLogSink() {
    exists(MethodCall ma |
      (
        // Log4j 2.x: org.apache.logging.log4j.Logger
        ma.getMethod().getDeclaringType().getASupertype*()
            .hasQualifiedName("org.apache.logging.log4j", "Logger")
        or
        // Log4j 1.x: org.apache.log4j.Logger (已 EOL，同样受影响的旧版本)
        ma.getMethod().getDeclaringType().getASupertype*()
            .hasQualifiedName("org.apache.log4j", "Category")
        or
        // SLF4J Logger（如后端绑定 Log4j 2）
        ma.getMethod().getDeclaringType().getASupertype*()
            .hasQualifiedName("org.slf4j", "Logger")
      )
      and ma.getMethod().getName() in [
        "trace", "debug", "info", "warn", "error", "fatal", "log", "printf", "format"
      ]
      // 第一个参数为消息内容（String / Object）
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

module Log4jConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n)   { n instanceof Log4jLogSink }
}

module Log4jFlow = TaintTracking::Global<Log4jConfig>;

from Log4jFlow::PathNode source, Log4jFlow::PathNode sink
select
  sink.getNode(),
  source.getNode().getLocation().getFile().getRelativePath() as source_file,
  source.getNode().getLocation().getStartLine()              as source_line,
  sink.getNode().getLocation().getFile().getRelativePath()   as sink_file,
  sink.getNode().getLocation().getStartLine()                as sink_line
