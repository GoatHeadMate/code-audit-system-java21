/**
 * 路径遍历污点追踪：用户输入流向文件系统操作。
 * sink 定义内联自共享库 sinks/PathSinks.qll。
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

/** Paths.get(first, more...) — 第 0 个参数 */
class NioPathsSink extends DataFlow::Node {
  NioPathsSink() {
    exists(MethodCall ma |
      ma.getMethod().hasQualifiedName("java.nio.file", "Paths", "get")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** Files read/write/delete/copy/move/newStream — 第 0 个参数（Path） */
class NioFilesSink extends DataFlow::Node {
  NioFilesSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files")
      and ma.getMethod().getName()
             .regexpMatch("read.*|write.*|delete.*|copy|move|new.*Stream|create.*")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** new File(path) / new File(parent, child) — 第 0 个参数 */
class FileConstructorSink extends DataFlow::Node {
  FileConstructorSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.io", "File")
      and this.asExpr() = cie.getArgument(0)
    )
  }
}

/** new FileInputStream / FileOutputStream / FileReader / FileWriter — 第 0 个参数 */
class FileStreamSink extends DataFlow::Node {
  FileStreamSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().getName()
         .regexpMatch("FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile")
      and this.asExpr() = cie.getArgument(0)
    )
  }
}

/** 统一路径 sink */
class AnyPathSink extends DataFlow::Node {
  AnyPathSink() {
    this instanceof NioPathsSink or
    this instanceof NioFilesSink or
    this instanceof FileConstructorSink or
    this instanceof FileStreamSink
  }
}

module PathTravConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n)   { n instanceof AnyPathSink }
}

module PathTravFlow = TaintTracking::Global<PathTravConfig>;

from PathTravFlow::PathNode source, PathTravFlow::PathNode sink
select
  sink.getNode(),
  source.getNode().getLocation().getFile().getRelativePath() as source_file,
  source.getNode().getLocation().getStartLine()              as source_line,
  sink.getNode().getLocation().getFile().getRelativePath()   as sink_file,
  sink.getNode().getLocation().getStartLine()                as sink_line
