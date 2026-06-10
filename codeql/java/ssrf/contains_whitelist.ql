/**
 * 检测使用 String.contains() 进行 URL/域名白名单校验的弱模式。
 * contains() 是子串匹配，攻击者可将白名单域名嵌入 URL 参数来绕过：
 *   http://evil.com?bypass=whitelisted.internal.com
 *
 * 修正（2026-06）：原版只匹配 MethodCall，漏掉方法引用形式。
 * 真实代码中常见 requestUrl::contains 方法引用（用于 stream().noneMatch()），
 * 这是 SSRF 白名单绕过的典型场景。现同时检测两种形式。
 */
import java

// ── 辅助谓词 ──────────────────────────────────────────────────────────

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

// ── Case 1: 直接调用 requestUrl.contains(x) 或 x.contains(whitelistEntry) ──

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
  "contains() 直接调用"                                   as pattern

union

// ── Case 2: 方法引用 requestUrl::contains 传给 stream().noneMatch/anyMatch ──

from MemberRefExpr mre
where
  mre.getMethod().hasName("contains")
  and mre.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")
  and isSecurityContextMethod(mre.getEnclosingCallable())
select
  mre.getLocation().getFile().getRelativePath()            as file,
  mre.getLocation().getStartLine()                         as line,
  mre.getEnclosingCallable().getName()                     as method_name,
  mre.getEnclosingCallable().getDeclaringType().getName()  as class_name,
  "contains() 方法引用（requestUrl::contains 等）"         as pattern
