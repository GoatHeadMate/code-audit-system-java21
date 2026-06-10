/**
 * 查找所有 Runtime.exec() 调用。
 * 字符串形式（单参数 exec(String)）shell 会解析元字符，视为危险；
 * 数组形式（exec(String[])）参数独立传递，相对安全。
 */
import java

from MethodCall ma
where
  ma.getMethod().getDeclaringType().getASupertype*()
    .hasQualifiedName("java.lang", "Runtime")
  and ma.getMethod().hasName("exec")
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.getArgument(0).getType().getName()        as arg_type
