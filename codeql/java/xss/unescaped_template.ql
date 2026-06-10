/**
 * 查找模板引擎中绕过自动转义的输出语法。
 * 覆盖 Thymeleaf th:utext / FreeMarker ${...?no_esc} / ${...!} 等常见不转义写法。
 */
import java

from Element e
where
  (
    e instanceof Annotation and
    e.(Annotation).getType().getQualifiedName().regexpMatch("(?i).*(Utext|Raw|unescaped|noescape).*")
  )
  or
  (
    e instanceof StringLiteral and
    e.(StringLiteral).getValue().regexpMatch(".*\\$\\{.*[?!].*\\}.*")
  )
select
  e.getLocation().getFile().getRelativePath() as file,
  e.getLocation().getStartLine()              as line,
  e.toString()                                as template_syntax
