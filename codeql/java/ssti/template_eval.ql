/**
 * 查找模板引擎执行点：SpEL、FreeMarker、Velocity、Thymeleaf。
 * 用于定位 SSTI 潜在 sink 位置。
 */
import java

from MethodCall ma
where
  // SpEL
  (
    ma.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("org.springframework.expression", "ExpressionParser")
    and ma.getMethod().hasName("parseExpression")
  )
  or
  // FreeMarker Template.process()
  (
    ma.getMethod().getDeclaringType()
        .hasQualifiedName("freemarker.template", "Template")
    and ma.getMethod().hasName("process")
  )
  or
  // Velocity engine.evaluate() / engine.mergeTemplate()
  (
    ma.getMethod().getDeclaringType()
        .hasQualifiedName("org.apache.velocity.app", "VelocityEngine")
    and ma.getMethod().getName().matches("evaluate|mergeTemplate|getTemplate")
  )
  or
  // Thymeleaf TemplateEngine.process()
  (
    ma.getMethod().getDeclaringType()
        .hasQualifiedName("org.thymeleaf", "TemplateEngine")
    and ma.getMethod().hasName("process")
  )
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.getMethod().getDeclaringType().getName()  as engine_type,
  ma.getMethod().getName()                     as method
