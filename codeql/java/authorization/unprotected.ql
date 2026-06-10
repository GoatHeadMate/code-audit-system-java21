/**
 * 查找有 HTTP 路由注解但缺少权限控制注解的方法。
 * 权限注解包括 @PreAuthorize / @Secured / @RolesAllowed / @PermitAll。
 * 缺少任一权限控制的接口即视为未受保护的端点。
 */
import java

from Annotation routeAnn, Method m
where
  m = routeAnn.getTarget()
  and routeAnn.getType().getName().regexpMatch(
    "RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping"
  )
  and not exists(Annotation secAnn |
    secAnn.getTarget() = m
    and secAnn.getType().getName().regexpMatch(
      "PreAuthorize|Secured|RolesAllowed|PermitAll"
    )
  )
select
  m.getLocation().getFile().getRelativePath() as file,
  m.getLocation().getStartLine()              as line,
  m.getName()                                 as method_name
