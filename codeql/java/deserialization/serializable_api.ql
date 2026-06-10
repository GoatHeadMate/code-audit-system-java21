/**
 * 查找实现 Serializable 接口且直接暴露在 HTTP 接口中的类。
 * 这些类被 @RequestBody / @RequestParam 接收，
 * 攻击者可能通过构造恶意序列化数据发起攻击。
 */
import java

from ClassOrInterface c, Annotation ann
where
  c.getASupertype*().hasQualifiedName("java.io", "Serializable")
  and ann.getType().getName().regexpMatch("RequestBody|RequestParam")
  and exists(Parameter p |
    p = ann.getTarget()
    and p.getType() = c
  )
select
  c.getLocation().getFile().getRelativePath() as file,
  c.getLocation().getStartLine()              as line,
  c.getName()                                 as class_name,
  "java.io.Serializable"                      as interface_name
