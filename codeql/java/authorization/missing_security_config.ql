/**
 * 检测 Spring Boot 项目缺少显式 SecurityFilterChain 配置的情况。
 *
 * 覆盖两种常见配置方式：
 *   1. 旧式: 继承 WebSecurityConfigurerAdapter 并覆写 configure(HttpSecurity)
 *   2. 新式 (Spring Security 5.7+): @Bean 方法返回 SecurityFilterChain
 *
 * 若项目使用 @SpringBootApplication 但两种配置均未找到，说明安全配置可能缺失。
 */
import java

/** 旧式安全配置：继承 WebSecurityConfigurerAdapter */
class LegacySecurityConfig extends Class {
  LegacySecurityConfig() {
    this.getAnAncestor().hasQualifiedName(
      "org.springframework.security.config.annotation.web.configuration",
      "WebSecurityConfigurerAdapter"
    )
  }
}

/** 新式安全配置：@Bean 方法返回 SecurityFilterChain */
class SecurityFilterChainBean extends Method {
  SecurityFilterChainBean() {
    this.getReturnType()
        .(RefType)
        .hasQualifiedName(
          "org.springframework.security.web",
          "SecurityFilterChain"
        )
    and exists(Annotation ann |
      ann.getTarget() = this
      and ann.getType().hasQualifiedName(
        "org.springframework.context.annotation", "Bean"
      )
    )
  }
}

/** Spring Boot 入口类 */
class SpringBootApp extends Class {
  SpringBootApp() {
    exists(Annotation ann |
      ann.getTarget() = this
      and ann.getType().getName() = "SpringBootApplication"
    )
  }
}

from SpringBootApp app
where
  // 没有旧式配置（CodeQL exists() 需要具名变量，不支持 _ 匿名占位）
  not exists(LegacySecurityConfig c | c = c)
  // 没有新式配置
  and not exists(SecurityFilterChainBean m | m = m)
select
  app.getLocation().getFile().getRelativePath() as file,
  app.getLocation().getStartLine()              as line,
  app.getName()                                 as class_name,
  "缺少 SecurityFilterChain / WebSecurityConfigurerAdapter 配置" as message
