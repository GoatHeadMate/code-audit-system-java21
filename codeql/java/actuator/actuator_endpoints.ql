/**
 * 查找项目中自定义的 Actuator 端点（@Endpoint / @RestControllerEndpoint 注解）。
 * 这些端点如果未受保护，攻击者可直接调用。
 */
import java

from Annotation ann, Method m
where
  ann.getType().getName().regexpMatch("Endpoint|RestControllerEndpoint|WebEndpoint")
  and (
    ann.getTarget() = m
    or ann.getTarget() = m.getDeclaringType()
  )
select
  m.getLocation().getFile().getRelativePath() as file,
  m.getLocation().getStartLine()              as line,
  m.getDeclaringType().getName()              as class_name,
  m.getName()                                 as method_name,
  ann.getType().getName()                     as endpoint_annotation
