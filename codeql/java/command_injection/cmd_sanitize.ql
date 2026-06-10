/**
 * 查找命令执行前对输入进行的 shell 元字符过滤或白名单校验。
 * 匹配对 & ; | ` $ ( ) < > \ " ' 等元字符的正则过滤。
 */
import java

from MethodCall ma
where
  exists(StringLiteral lit |
    lit = ma.getAnArgument()
    and lit.getValue().regexpMatch(
      ".*[;&|`$()<>\\\\\"'].*"
    )
  )
  and ma.getMethod().getName().regexpMatch(
    "replaceAll|replace|matches|contains|equals|filter"
  )
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.toString()                                as validation_pattern
