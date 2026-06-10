/**
 * Java 命令注入 Sink 库（共享）。
 *
 * 涵盖：Runtime.exec()、ProcessBuilder、
 * Apache Commons Exec CommandLine.parse()。
 */
import java
import semmle.code.java.dataflow.DataFlow

/** Runtime.exec(cmd) — 第 0 个参数 */
class RuntimeExecSink extends DataFlow::Node {
  RuntimeExecSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("java.lang", "Runtime")
      and ma.getMethod().hasName("exec")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** new ProcessBuilder(cmd, ...) — 第 0 个参数 */
class ProcessBuilderConstructorSink extends DataFlow::Node {
  ProcessBuilderConstructorSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.lang", "ProcessBuilder")
      and this.asExpr() = cie.getArgument(0)
    )
  }
}

/** ProcessBuilder.command(cmd, ...) — 第 0 个参数 */
class ProcessBuilderCommandSink extends DataFlow::Node {
  ProcessBuilderCommandSink() {
    exists(MethodCall ma |
      ma.getMethod().hasQualifiedName("java.lang", "ProcessBuilder", "command")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** Apache Commons Exec CommandLine.parse(cmdStr) */
class CommonsExecSink extends DataFlow::Node {
  CommonsExecSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("org.apache.commons.exec", "CommandLine")
      and ma.getMethod().hasName("parse")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** 统一命令注入 sink */
class AnyCommandSink extends DataFlow::Node {
  AnyCommandSink() {
    this instanceof RuntimeExecSink or
    this instanceof ProcessBuilderConstructorSink or
    this instanceof ProcessBuilderCommandSink or
    this instanceof CommonsExecSink
  }
}
