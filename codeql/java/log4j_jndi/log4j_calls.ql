/**
 * 枚举所有 Log4j / SLF4J Logger 调用点（不区分来源），
 * 辅助 LLM 判断哪些日志语句参数含有用户输入。
 */
import java

from MethodCall ma
where
  (
    ma.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("org.apache.logging.log4j", "Logger")
    or
    ma.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("org.apache.log4j", "Category")
    or
    ma.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("org.slf4j", "Logger")
  )
  and ma.getMethod().getName() in [
    "trace", "debug", "info", "warn", "error", "fatal", "log"
  ]
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.getMethod().getName()                     as log_level,
  ma.getArgument(0).toString()                 as message_arg
