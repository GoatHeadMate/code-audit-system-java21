/**
 * 查找所有带 HTTP 路由注解的方法。
 * 覆盖 Spring MVC @RequestMapping / @GetMapping / @PostMapping / @PutMapping
 * / @DeleteMapping / @PatchMapping 等常见路由映射注解。
 */
import java

from Annotation ann, Method m
where
  m = ann.getTarget()
  and ann.getType().getName().regexpMatch(
    "RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping"
  )
select
  m.getLocation().getFile().getRelativePath() as file,
  m.getLocation().getStartLine()              as line,
  m.getName()                                 as method_name,
  ann.getType().getName()                     as annotation
