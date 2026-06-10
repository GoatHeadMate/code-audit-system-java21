/**
 * 检测使用 String.contains() 进行 URL/域名白名单校验的弱模式。
 * contains() 是子串匹配，攻击者可将白名单域名嵌入 URL 参数来绕过：
 *   http://evil.com?bypass=whitelisted.internal.com
 *
 * 同时检测两种形式：
 *   - 直接调用：requestUrl.contains(entry)
 *   - 方法引用：requestUrl::contains（用于 stream().noneMatch/anyMatch）
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

from Expr e, string pattern
where
  // Case 1: 直接调用 requestUrl.contains(x) 或 x.contains(whitelistEntry)
  (
    e.(MethodCall).getMethod().hasName("contains")
    and e.(MethodCall).getMethod().getDeclaringType()
            .hasQualifiedName("java.lang", "String")
    and (
      isSecurityContextMethod(e.getEnclosingCallable())
      or exists(Variable v |
        v.getAnAccess() = e.(MethodCall).getQualifier() and hasUrlVarName(v)
      )
      or exists(Variable v |
        v.getAnAccess() = e.(MethodCall).getArgument(0) and hasUrlVarName(v)
      )
    )
    and pattern = "contains() 直接调用"
  )
  or
  // Case 2: 方法引用 requestUrl::contains 传给 stream().noneMatch/anyMatch
  (
    e.(MemberRefExpr).getBaseName() = "contains"
    and e.(MemberRefExpr).getQualifier().getType()
            .(RefType).hasQualifiedName("java.lang", "String")
    and (
      isSecurityContextMethod(e.getEnclosingCallable())
      or exists(Variable v |
        v.getAnAccess() = e.(MemberRefExpr).getQualifier() and hasUrlVarName(v)
      )
    )
    and pattern = "contains() 方法引用（requestUrl::contains 等）"
  )
select
  e.getLocation().getFile().getRelativePath()            as file,
  e.getLocation().getStartLine()                         as line,
  e.getEnclosingCallable().getName()                     as method_name,
  e.getEnclosingCallable().getDeclaringType().getName()  as class_name,
  pattern
