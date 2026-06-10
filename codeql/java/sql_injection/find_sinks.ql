/**
 * 查找所有 SQL 执行点（sink 点）。
 * sink 定义来自共享库 sinks/SqlSinks.qll，覆盖 JDBC / MyBatis / Hibernate / JPA。
 */
import java

// ── SQL MethodCall sinks（内联）──────────────────────────────────────
private class JdbcExecutionCall extends MethodCall {
  JdbcExecutionCall() {
    this.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("java.sql", "Statement")
    and this.getMethod().getName().matches("execute%")
  }
}
private class MyBatisSqlSessionCall extends MethodCall {
  MyBatisSqlSessionCall() {
    this.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("org.apache.ibatis.session", "SqlSession")
    and this.getMethod().getName().regexpMatch("select.*|insert|update|delete")
  }
}
private class HibernateQueryCall extends MethodCall {
  HibernateQueryCall() {
    this.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("org.hibernate", "Session")
    and this.getMethod().getName() in ["createQuery", "createSQLQuery", "createNativeQuery"]
  }
}
private class JpaQueryCall extends MethodCall {
  JpaQueryCall() {
    this.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("javax.persistence", "EntityManager")
    and this.getMethod().getName() in ["createNativeQuery", "createQuery"]
  }
}
class AnySqlExecutionCall extends MethodCall {
  AnySqlExecutionCall() {
    this instanceof JdbcExecutionCall or
    this instanceof MyBatisSqlSessionCall or
    this instanceof HibernateQueryCall or
    this instanceof JpaQueryCall
  }
}
// ─────────────────────────────────────────────────────────────────────

from AnySqlExecutionCall ma
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.getMethod().getName()                     as sink_method,
  ma.getMethod().getDeclaringType().getName()  as sink_class
