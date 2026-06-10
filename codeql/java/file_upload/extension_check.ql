/**
 * 查找对原始文件名的扩展名校验代码。
 * 匹配对 getOriginalFilename() 返回值进行 contains/endsWith/matches
 * 等字符串比对操作的代码。
 * has_whitelist_pattern 根据是否使用 equalsIgnoreCase/matches 正则判断。
 */
import java

from MethodCall ma
where
  ma.getMethod().hasName("getOriginalFilename")
  and exists(MethodCall check |
    check.getMethod().getName().regexpMatch("contains|endsWith|matches|equalsIgnoreCase")
    and check.getQualifier().getAChildExpr*() = ma
  )
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.toString()                                as expression,
  "检查扩展名校验逻辑是否使用白名单"           as has_whitelist_pattern
