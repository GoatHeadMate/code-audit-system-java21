/**
 * 检测 Spring Boot 应用是否完全缺少 SecurityFilterChain 配置。
 *
 * 当项目引入了 spring-boot-starter-actuator 但没有任何 Spring Security 配置时，
 * 所有 Actuator 端点（/actuator/env、/actuator/heapdump 等）均无认证保护，
 * 可直接被匿名访问，构成信息泄露乃至 RCE 风险。
 *
 * 覆盖两种配置缺失场景：
 *   1. 未继承 WebSecurityConfigurerAdapter（旧式）
 *   2. 未声明返回 SecurityFilterChain 的 @Bean 方法（新式）
 */
import java

/** 旧式安全配置：继承 WebSecurityConfigurerAdapter */
private class LegacySecurityConfig extends Class {
  LegacySecurityConfig() {
    this.getAnAncestor().hasQualifiedName(
      "org.springframework.security.config.annotation.web.configuration",
      "WebSecurityConfigurerAdapter"
    )
  }
}

/** 新式安全配置：@Bean 方法返回 SecurityFilterChain */
private class SecurityFilterChainBean extends Method {
  SecurityFilterChainBean() {
    this.getReturnType()
        .(RefType)
        .hasQualifiedName("org.springframework.security.web", "SecurityFilterChain")
    and exists(Annotation ann |
      ann.getTarget() = this
      and ann.getType().hasQualifiedName("org.springframework.context.annotation", "Bean")
    )
  }
}

/** Spring Boot 入口类 */
private class SpringBootApp extends Class {
  SpringBootApp() {
    exists(Annotation ann |
      ann.getTarget() = this
      and ann.getType().getName() = "SpringBootApplication"
    )
  }
}

from SpringBootApp app
where
  // 既没有旧式配置也没有新式配置 → 整个应用无 Spring Security 防护
  not exists(LegacySecurityConfig c | c = c)
  and not exists(SecurityFilterChainBean m | m = m)
select
  app.getLocation().getFile().getRelativePath() as file,
  app.getLocation().getStartLine()              as line,
  app.getName()                                 as class_name,
  "未检测到任何 SecurityFilterChain / WebSecurityConfigurerAdapter，Actuator 端点可能完全无认证保护" as message
