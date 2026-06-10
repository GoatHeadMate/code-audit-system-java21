/**
 * 查找 Zip Slip 模式：压缩包条目名直接用于文件路径构造。
 * 匹配 ZipEntry.getName() 的返回值流入文件写入操作的路径参数。
 */
import java

from MethodCall entryCall, MethodCall fileOp
where
  entryCall.getMethod().hasQualifiedName("java.util.zip", "ZipEntry", "getName")
  and (
    fileOp.getMethod().hasQualifiedName("java.nio.file", "Files", ["write", "copy", "newOutputStream"])
    or fileOp.getMethod().getDeclaringType().getASupertype*()
      .hasQualifiedName("java.io", "FileOutputStream")
  )
  and fileOp.getArgument(0).getAChildExpr*() = entryCall
select
  fileOp.getLocation().getFile().getRelativePath() as file,
  fileOp.getLocation().getStartLine()              as line,
  entryCall.toString()                             as entry_usage,
  fileOp.getArgument(0).toString()                 as target_path_expr
