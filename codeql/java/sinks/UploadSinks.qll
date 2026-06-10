/**
 * Java 文件上传 Sink 库（共享）。
 *
 * 涵盖：Spring MultipartFile.transferTo()、
 * Servlet Part.write()、Commons FileUpload.write()。
 */
import java
import semmle.code.java.dataflow.DataFlow

/** MultipartFile.transferTo(dest) — Spring 文件保存目标路径 */
class MultipartTransferSink extends DataFlow::Node {
  MultipartTransferSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("org.springframework.web.multipart", "MultipartFile")
      and ma.getMethod().hasName("transferTo")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** javax.servlet.http.Part.write(fileName) — Servlet 3.0 文件保存 */
class ServletPartWriteSink extends DataFlow::Node {
  ServletPartWriteSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("javax.servlet.http", "Part")
      and ma.getMethod().hasName("write")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** Commons FileUpload FileItem.write(file) */
class CommonsUploadSink extends DataFlow::Node {
  CommonsUploadSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("org.apache.commons.fileupload", "FileItem")
      and ma.getMethod().hasName("write")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** 统一文件上传 sink */
class AnyUploadSink extends DataFlow::Node {
  AnyUploadSink() {
    this instanceof MultipartTransferSink or
    this instanceof ServletPartWriteSink or
    this instanceof CommonsUploadSink
  }
}
