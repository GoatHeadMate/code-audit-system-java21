/**
 * 查找 Spring Security 配置中对 Actuator 端点的保护情况。
 *
 * 检测两类情况：
 *   1. SecurityFilterChain/@Bean 方法中包含 /actuator 路径匹配规则
 *   2. configure(HttpSecurity) 中 requestMatchers 涉及 actuator 的配置
 */
import java

/** SecurityFilterChain @Bean 方法 */
class SecurityFilterChainMethod extends Method {
  SecurityFilterChainMethod() {
    this.getReturnType().(RefType)
        .hasQualifiedName("org.springframework.security.web", "SecurityFilterChain")
    and exists(Annotation ann |
      ann.getTarget() = this
      and ann.getType().hasQualifiedName("org.springframework.context.annotation", "Bean")
    )
  }
}

/** 旧式 configure(HttpSecurity) */
class HttpSecurityConfigureMethod extends Method {
  HttpSecurityConfigureMethod() {
    this.getName() = "configure"
    and this.getNumberOfParameters() = 1
    and this.getParameter(0).getType().getName().matches("%HttpSecurity%")
  }
}

/** 方法体中是否引用了 /actuator 路径 */
predicate referencesActuator(Method m) {
  exists(StringLiteral s |
    s.getParent+() = m.getBody()
    and s.getLiteral().matches("%/actuator%")
  )
}

string actuatorRule(Method m) {
  if referencesActuator(m)
  then result = "包含 /actuator 路径规则"
  else result = "未提及 /actuator 路径"
}

from Method m, string kind
where
  (m instanceof SecurityFilterChainMethod and kind = "SecurityFilterChain @Bean")
  or (m instanceof HttpSecurityConfigureMethod and kind = "configure(HttpSecurity)")
select
  m.getLocation().getFile().getRelativePath() as file,
  m.getLocation().getStartLine()              as line,
  m.getDeclaringType().getName()              as class_name,
  kind                                        as config_kind,
  actuatorRule(m)                             as actuator_rule
