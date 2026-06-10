/**
 * 查找 ProcessBuilder 的使用。
 * ProcessBuilder 默认参数独立传递不经过 shell，
 * 但若使用 command(String) 拼接或 user input 直接作为参数仍存在风险。
 */
import java

from MethodCall ma
where
  ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder")
  and ma.getMethod().hasName("ProcessBuilder")
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.getArgument(0).toString()                 as command_source
