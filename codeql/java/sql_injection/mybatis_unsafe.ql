/**
 * 查找 MyBatis Mapper XML 中使用 ${} 字符串插值的位置。
 * ${} 直接将用户输入拼接进 SQL，应改为 #{} 参数化占位符。
 */
import java

from StringLiteral s
where s.getLiteral().regexpMatch(".*\\$\\{.*\\}.*")
select
  s.getLocation().getFile().getRelativePath() as file,
  s.getLocation().getStartLine()              as line,
  s.getLiteral()                              as unsafe_expression,
  "MyBatis ${} 字符串插值，存在 SQL 注入风险"   as message
