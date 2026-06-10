/**
 * 命令注入污点追踪：用户输入流向命令执行方法。
 *
 * 关键修正（2026-06）：
 *   ProcessBuilderShellCmdSink 专门处理 bash/sh -c 模式。
 *   原 ProcessBuilderConstructorSink 跟踪 arg[0]，即 "/bin/bash" 字面量，
 *   该参数永远不可能被污染，导致污点追踪从未找到 bash -c 命令注入路径。
 *   正确的 sink 是 arg[2]（传给 -c 的命令字符串），bash 会解析其中的元字符。
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

// ── Command sinks ────────────────────────────────────────────────────
private class RuntimeExecSink extends DataFlow::Node {
  RuntimeExecSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("java.lang", "Runtime")
      and ma.getMethod().hasName("exec")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/**
 * new ProcessBuilder("/bin/bash", "-c", <TAINTED>) — 命令字符串在 arg[2]。
 * bash -c 会解析 $()、``、;、&& 等，任何拼接的外部输入均可 RCE。
 */
private class ProcessBuilderShellCmdSink extends DataFlow::Node {
  ProcessBuilderShellCmdSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.lang", "ProcessBuilder")
      and cie.getNumArgument() >= 3
      and cie.getArgument(0).(StringLiteral).getValue().regexpMatch("(.*/bin/)?(ba)?sh")
      and cie.getArgument(1).(StringLiteral).getValue() = "-c"
      and this.asExpr() = cie.getArgument(2)
    )
  }
}

/**
 * new ProcessBuilder(<TAINTED>, ...) — 非 shell wrapper 场景，可执行文件名被污染。
 * 排除 bash/sh 模式（由 ProcessBuilderShellCmdSink 处理）。
 */
private class ProcessBuilderExecSink extends DataFlow::Node {
  ProcessBuilderExecSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.lang", "ProcessBuilder")
      and this.asExpr() = cie.getArgument(0)
      and not cie.getArgument(0).(StringLiteral).getValue()
              .regexpMatch("(.*/bin/)?(ba)?sh")
    )
  }
}

private class ProcessBuilderCommandSink extends DataFlow::Node {
  ProcessBuilderCommandSink() {
    exists(MethodCall ma |
      ma.getMethod().hasQualifiedName("java.lang", "ProcessBuilder", "command")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

private class CommonsExecSink extends DataFlow::Node {
  CommonsExecSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("org.apache.commons.exec", "CommandLine")
      and ma.getMethod().hasName("parse")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

private class AnyCommandSink extends DataFlow::Node {
  AnyCommandSink() {
    this instanceof RuntimeExecSink           or
    this instanceof ProcessBuilderShellCmdSink or
    this instanceof ProcessBuilderExecSink    or
    this instanceof ProcessBuilderCommandSink or
    this instanceof CommonsExecSink
  }
}
// ─────────────────────────────────────────────────────────────────────

module CmdInjConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n)   { n instanceof AnyCommandSink }
}

module CmdInjFlow = TaintTracking::Global<CmdInjConfig>;

from CmdInjFlow::PathNode source, CmdInjFlow::PathNode sink
select
  sink.getNode(),
  source.getNode().getLocation().getFile().getRelativePath() as source_file,
  source.getNode().getLocation().getStartLine()              as source_line,
  sink.getNode().getLocation().getFile().getRelativePath()   as sink_file,
  sink.getNode().getLocation().getStartLine()                as sink_line
