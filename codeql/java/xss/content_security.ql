/**
 * 查找安全响应头的设置情况。
 * 覆盖 Content-Type（charset 声明）、X-XSS-Protection、
 * Content-Security-Policy / X-Content-Type-Options 等安全头。
 */
import java

from MethodCall ma
where
  ma.getMethod().hasName("setHeader")
  and exists(StringLiteral key |
    key = ma.getArgument(0)
    and key.getValue().regexpMatch(
      "(?i).*(Content-Type|X-XSS-Protection|Content-Security-Policy|X-Content-Type-Options).*"
    )
  )
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.getArgument(0).toString()                 as header_name,
  ma.getArgument(1).toString()                 as header_value
