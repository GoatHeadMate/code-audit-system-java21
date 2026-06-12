/**
 * 检测使用 String.contains() 进行 URL/域名白名单校验的弱模式。
 * contains() 是子串匹配，攻击者可将白名单域名嵌入 URL 参数来绕过：
 *   http://evil.com?bypass=whitelisted.internal.com
 */
import java

private predicate isSecurityContextMethod(Callable c) {
  c.getName().regexpMatch(
    "(?i).*(check|valid|verify|filter|white|allow|url|request|auth|match).*"
  )
}

private predicate hasUrlVarName(Variable v) {
  v.getName().regexpMatch(
    "(?i).*(url|uri|host|domain|white|allow|endpoint|request|addr).*"
  )
}

from MethodCall ma
where
  ma.getMethod().hasName("contains")
  and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")
  and (
    isSecurityContextMethod(ma.getEnclosingCallable())
    or exists(Variable v |
      v.getAnAccess() = ma.getQualifier() and hasUrlVarName(v)
    )
    or exists(Variable v |
      v.getAnAccess() = ma.getArgument(0) and hasUrlVarName(v)
    )
  )
select
  ma.getLocation().getFile().getRelativePath()            as file,
  ma.getLocation().getStartLine()                         as line,
  ma.getEnclosingCallable().getName()                     as method_name,
  ma.getEnclosingCallable().getDeclaringType().getName()  as class_name,
  "contains() 白名单校验（可被子串绕过）"                  as pattern
