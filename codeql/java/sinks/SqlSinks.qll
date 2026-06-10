/**
 * Java SQL 注入 Sink 库（共享）。
 *
 * 提供两类导出：
 *   - XxxExecutionCall  — MethodCall 子类，用于 find_sinks.ql 枚举查询
 *   - SqlSink           — DataFlow::Node 子类，用于 trace_taint.ql 污点追踪
 *
 * 涵盖范围：JDBC Statement/PreparedStatement、MyBatis SqlSession、
 * Hibernate Session、JPA EntityManager。
 */
import java
import semmle.code.java.dataflow.DataFlow

// ─── MethodCall 级别（枚举用） ───────────────────────────────────────────────

/** JDBC Statement.execute*() */
class JdbcExecutionCall extends MethodCall {
  JdbcExecutionCall() {
    this.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("java.sql", "Statement")
    and this.getMethod().getName().matches("execute%")
  }
  /** SQL 字符串参数（第 0 个参数） */
  Expr getSqlArg() { result = this.getArgument(0) }
}

/** MyBatis SqlSession.select* / insert / update / delete */
class MyBatisSqlSessionCall extends MethodCall {
  MyBatisSqlSessionCall() {
    this.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("org.apache.ibatis.session", "SqlSession")
    and this.getMethod().getName().regexpMatch("select.*|insert|update|delete")
  }
  Expr getStatementArg() { result = this.getArgument(0) }
}

/** Hibernate Session.createQuery / createSQLQuery / createNativeQuery */
class HibernateQueryCall extends MethodCall {
  HibernateQueryCall() {
    this.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("org.hibernate", "Session")
    and this.getMethod().getName() in [
        "createQuery", "createSQLQuery", "createNativeQuery"
    ]
  }
  Expr getHqlArg() { result = this.getArgument(0) }
}

/** JPA EntityManager.createNativeQuery / createQuery */
class JpaQueryCall extends MethodCall {
  JpaQueryCall() {
    this.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("javax.persistence", "EntityManager")
    and this.getMethod().getName() in ["createNativeQuery", "createQuery"]
  }
  Expr getQueryArg() { result = this.getArgument(0) }
}

/** 所有 SQL 执行调用（枚举查询用的联合类） */
class AnySqlExecutionCall extends MethodCall {
  AnySqlExecutionCall() {
    this instanceof JdbcExecutionCall or
    this instanceof MyBatisSqlSessionCall or
    this instanceof HibernateQueryCall or
    this instanceof JpaQueryCall
  }
}

// ─── DataFlow::Node 级别（污点追踪用） ──────────────────────────────────────

/** JDBC SQL 参数节点 */
class JdbcSqlSink extends DataFlow::Node {
  JdbcSqlSink() {
    exists(JdbcExecutionCall mc | this.asExpr() = mc.getSqlArg())
  }
}

/** MyBatis statement ID 参数节点 */
class MyBatisSqlSink extends DataFlow::Node {
  MyBatisSqlSink() {
    exists(MyBatisSqlSessionCall mc | this.asExpr() = mc.getStatementArg())
  }
}

/** Hibernate / JPA HQL 参数节点 */
class HibernateSqlSink extends DataFlow::Node {
  HibernateSqlSink() {
    exists(HibernateQueryCall mc | this.asExpr() = mc.getHqlArg())
    or
    exists(JpaQueryCall mc | this.asExpr() = mc.getQueryArg())
  }
}

/** 污点追踪使用的统一 SQL sink */
class SqlSink extends DataFlow::Node {
  SqlSink() {
    this instanceof JdbcSqlSink or
    this instanceof MyBatisSqlSink or
    this instanceof HibernateSqlSink
  }
}
