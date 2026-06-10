/**
 * 二阶 SQL 注入检测：查询数据库读出的数据再次用于 SQL 拼接。
 * 场景：用户输入先存入数据库，之后被读取出来再拼接进 SQL。
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

/** ResultSet.getString / getObject / getInt 等 — 从数据库读出的值作为污点源 */
class DbReadSource extends DataFlow::Node {
  DbReadSource() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
         .hasQualifiedName("java.sql", "ResultSet")
      and ma.getMethod().getName().matches("get%")
      and this.asExpr() = ma
    )
  }
}

module SecondOrderConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof DbReadSource }
  predicate isSink(DataFlow::Node n)   { n instanceof SqlSink }
}

module SecondOrderFlow = TaintTracking::Global<SecondOrderConfig>;

from SecondOrderFlow::PathNode source, SecondOrderFlow::PathNode sink
select
  sink.getNode(),
  source, sink,
  source.getNode().getLocation().getFile().getRelativePath() as src_file,
  source.getNode().getLocation().getStartLine()              as src_line,
  sink.getNode().getLocation().getFile().getRelativePath()   as sink_file,
  sink.getNode().getLocation().getStartLine()                as sink_line,
  "二阶 SQL 注入：数据库读出值流向 SQL 执行点"               as message
