/**
 * 查找接收文件上传的 HTTP 接口。
 * 覆盖 MultipartFile / Part / InputStream 等常见文件接收参数类型。
 */
import java

from Annotation ann, Method m, Parameter p
where
  m = ann.getTarget()
  and ann.getType().getName().regexpMatch(
    "RequestMapping|PostMapping|PutMapping|PatchMapping"
  )
  and p = m.getAParameter()
  and (
    p.getType().getName().regexpMatch("MultipartFile|Part|InputStream|FilePart|FileItem")
    or p.getType().getName().matches("%Multipart%")
  )
select
  m.getLocation().getFile().getRelativePath() as file,
  m.getLocation().getStartLine()              as line,
  m.getName()                                 as method_name,
  p.getType().getName()                       as param_type
