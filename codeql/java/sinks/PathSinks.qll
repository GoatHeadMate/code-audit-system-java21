/**
 * Java 路径遍历 Sink 库（共享）。
 *
 * 涵盖：java.io.File 构造器、java.io 流构造器、
 * java.nio.file.Paths.get()、java.nio.file.Files 操作方法。
 */
import java
import semmle.code.java.dataflow.DataFlow

/** Paths.get(first, more...) — 第 0 个参数 */
class NioPathsSink extends DataFlow::Node {
  NioPathsSink() {
    exists(MethodCall ma |
      ma.getMethod().hasQualifiedName("java.nio.file", "Paths", "get")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** Files.read* / write* / delete* / copy / move / new*Stream — 第 0 个参数（Path） */
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
