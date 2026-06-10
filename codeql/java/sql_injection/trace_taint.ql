/**
 * 端到端污点追踪：从 HTTP 请求参数到 SQL 执行点。
 * sink 定义来自共享库 sinks/SqlSinks.qll（SqlSink 类）。
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

// ── SQL sinks（内联）─────────────────────────────────────────────────
private class JdbcExecutionCall extends MethodCall {
  JdbcExecutionCall() {
    this.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("java.sql", "Statement")
    and this.getMethod().getName().matches("execute%")
  }
  Expr getSqlArg() { result = this.getArgument(0) }
}
private class MyBatisSqlSessionCall extends MethodCall {
  MyBatisSqlSessionCall() {
    this.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("org.apache.ibatis.session", "SqlSession")
    and this.getMethod().getName().regexpMatch("select.*|insert|update|delete")
  }
  Expr getStatementArg() { result = this.getArgument(0) }
}
private class HibernateQueryCall extends MethodCall {
  HibernateQueryCall() {
    this.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("org.hibernate", "Session")
    and this.getMethod().getName() in ["createQuery", "createSQLQuery", "createNativeQuery"]
  }
  Expr getHqlArg() { result = this.getArgument(0) }
}
private class JpaQueryCall extends MethodCall {
  JpaQueryCall() {
    this.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("javax.persistence", "EntityManager")
    and this.getMethod().getName() in ["createNativeQuery", "createQuery"]
  }
  Expr getQueryArg() { result = this.getArgument(0) }
}
private class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(JdbcExecutionCall mc | this.asExpr() = mc.getSqlArg())
    or exists(MyBatisSqlSessionCall mc | this.asExpr() = mc.getStatementArg())
    or exists(HibernateQueryCall mc | this.asExpr() = mc.getHqlArg())
    or exists(JpaQueryCall mc | this.asExpr() = mc.getQueryArg())
  }
}
// ─────────────────────────────────────────────────────────────────────

module SqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n)   { n instanceof SqlSink }
}

module SqlInjectionFlow = TaintTracking::Global<SqlInjectionConfig>;

from SqlInjectionFlow::PathNode source, SqlInjectionFlow::PathNode sink
select
  sink.getNode(),
  source, sink,
  source.getNode().getLocation().getFile().getRelativePath() as src_file,
  source.getNode().getLocation().getStartLine()              as src_line,
  sink.getNode().getLocation().getFile().getRelativePath()   as sink_file,
  sink.getNode().getLocation().getStartLine()                as sink_line
