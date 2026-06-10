// 查找 JAX-RS 端点方法中缺失鉴权调用的端点。
// 仅当同类中存在其他端点方法调用了鉴权方法时才报告（对比检测），
// 避免对全局统一鉴权的项目产生误报。
//
// 鉴权方法模式: checkAuth* / checkOps* / authorize / isAuth / hasRole / verifyToken 等。
// HTTP 注解: JAX-RS (@POST/@GET/@PUT/@DELETE) 及 Spring MVC 注解。
import java

private predicate isHttpEndpoint(Method m) {
  exists(Annotation a |
    a.getTarget() = m and
    a.getType().getName().regexpMatch(
      "POST|GET|PUT|DELETE|PATCH|RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping"
    )
  )
}

private predicate hasAuthCall(Method m) {
  exists(MethodCall mc |
    mc.getEnclosingCallable() = m and
    mc.getMethod().getName().regexpMatch(
      "(?i).*(check.*auth|check.*ops|check.*perm|authorize|isAuth|hasRole|hasAuth|requireRole|verifyToken|validateToken|requireAuth|assertAuth|ensureAuth).*"
    )
  )
}

from Method m, RefType c
where
  c = m.getDeclaringType()
  and isHttpEndpoint(m)
  and not hasAuthCall(m)
  // 对比检测：同类中其他端点方法存在鉴权调用
  and exists(Method sibling |
    sibling.getDeclaringType() = c
    and sibling != m
    and isHttpEndpoint(sibling)
    and hasAuthCall(sibling)
  )
select
  m.getLocation().getFile().getRelativePath() as file,
  m.getLocation().getStartLine()              as line,
  m.getName()                                 as method_name,
  c.getName()                                 as class_name,
  "同类中其他端点有鉴权，此方法缺失"          as risk
