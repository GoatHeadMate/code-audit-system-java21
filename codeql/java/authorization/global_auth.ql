/**
 * 查找全局安全配置方法，判断项目是否有兜底的全局权限拦截。
 * 查找 configure(HttpSecurity) 及类似全局过滤器/拦截器配置方法。
 */
import java

from Method m
where
  m.getName() = "configure"
  and m.getNumberOfParameters() >= 1
  and m.getParameter(0).getType().getName().matches("%HttpSecurity%")
select
  m.getLocation().getFile().getRelativePath() as file,
  m.getLocation().getStartLine()              as line,
  m.getDeclaringType().getName()              as class_name,
  m.getName()                                 as method_name
