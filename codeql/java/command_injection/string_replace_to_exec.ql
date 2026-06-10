/**
 * 检测 String.replace("${...}", value) 模板替换模式。
 * 当代码使用 String.replace 将模板占位符替换为外部值，且替换结果
 * 可能流向命令执行或 SQL 查询时，存在注入风险。
 * 典型案例: TaskUtil.generateQuery() 将 ${dn} 替换为用户输入后拼入 bash 命令。
 */
import java

from MethodCall ma, StringLiteral pattern
where
  ma.getMethod().hasName("replace")
  and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")
  and ma.getNumArgument() = 2
  and pattern = ma.getArgument(0)
  and pattern.getValue().regexpMatch(".*\\$\\{.*\\}.*")
select
  ma.getLocation().getFile().getRelativePath()            as file,
  ma.getLocation().getStartLine()                         as line,
  pattern.getValue()                                      as template_key,
  ma.getArgument(1).toString()                            as replacement_value,
  ma.getEnclosingCallable().getName()                     as method_name,
  ma.getEnclosingCallable().getDeclaringType().getName()  as class_name
