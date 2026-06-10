/**
 * 查找 HTTP 接口中参数名包含资源 ID 标识的方法（IDOR 候选点）。
 * 匹配参数名中包含 id / userId / ownerId / memberId 等模式的接口。
 */
import java

from Annotation ann, Method m, Parameter p
where
  m = ann.getTarget()
  and ann.getType().getName().regexpMatch(
    "RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping"
  )
  and p = m.getAParameter()
  and p.getName().regexpMatch(
    "(?i).*(id|userId|ownerId|memberId|accountId|orderId|resourceId|uuid).*"
  )
select
  m.getLocation().getFile().getRelativePath() as file,
  m.getLocation().getStartLine()              as line,
  m.getName()                                 as method_name,
  p.getName()                                 as param_name
