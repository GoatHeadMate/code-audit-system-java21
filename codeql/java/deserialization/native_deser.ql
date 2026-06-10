/**
 * 查找原生反序列化入口：ObjectInputStream.readObject() 调用。
 *
 * 修正（2026-06）：原版只枚举所有 readObject()，导致以下误报：
 *   - 覆盖了 resolveClass() 进行类白名单过滤的安全子类
 *   - 类名含 Secure/Validat/Filter/Whitelist 的安全封装
 * 现通过两个排除谓词减少误报。
 */
import java

/**
 * 类自身（或其任一超类）声明了 resolveClass() 方法，
 * 说明使用了类白名单过滤，是常见的反序列化防护手段。
 */
private predicate declaresResolveClass(RefType c) {
  exists(Method m |
    m.getDeclaringType() = c
    and m.getName() = "resolveClass"
  )
}

/**
 * 类名含安全语义关键词：Secure / Validat / Filter / Whitelist / Safe。
 * 例如 SecureObjectInputStream、ValidatingObjectInputStream。
 */
private predicate hasSecureClassName(RefType c) {
  c.getName().regexpMatch(
    "(?i).*(Secure|Validat|Filter|Whitelist|WhiteList|Safe|Filtered).*"
  )
}

from MethodCall ma, RefType encClass
where
  ma.getMethod().getDeclaringType().getASupertype*()
    .hasQualifiedName("java.io", "ObjectInputStream")
  and ma.getMethod().getName() = "readObject"
  and encClass = ma.getEnclosingCallable().getDeclaringType()
  and not declaresResolveClass(encClass)
  and not hasSecureClassName(encClass)
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.getEnclosingCallable().getName()          as caller,
  encClass.getName()                           as class_name
