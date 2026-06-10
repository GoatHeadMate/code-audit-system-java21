/**
 * 查找对 Content-Type / MIME 类型进行校验的代码。
 * 匹配对 getContentType() 返回值进行比较或正则匹配的操作。
 */
import java

from MethodCall ma
where
  ma.getMethod().hasName("getContentType")
  and exists(MethodCall check |
    check.getMethod().getName().regexpMatch(
      "equals|contains|matches|equalsIgnoreCase|startsWith"
    )
    and check.getQualifier().getAChildExpr*() = ma
  )
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.toString()                                as expression
