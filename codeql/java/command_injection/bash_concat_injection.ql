/**
 * 检测通过 shell -c 执行动态命令的模式。
 * 当 ProcessBuilder 以 "/bin/bash"/"/bin/sh" + "-c" + 非字面量参数调用时，
 * bash 会解析命令字符串中的 $()、``、;、&& 等元字符，
 * 若该字符串包含拼接的外部输入则导致命令注入。
 *
 * 覆盖模式:
 *   new ProcessBuilder("/bin/bash", "-c", dynamicCmd)
 *   new ProcessBuilder("/bin/sh", "-c", dynamicCmd)
 */
import java

from ClassInstanceExpr cie, Expr cmdArg
where
  cie.getConstructedType().hasQualifiedName("java.lang", "ProcessBuilder")
  and cie.getNumArgument() >= 3
  and cie.getArgument(0).(StringLiteral).getValue().regexpMatch("(.*/bin/)?(ba)?sh")
  and cie.getArgument(1).(StringLiteral).getValue() = "-c"
  and cmdArg = cie.getArgument(2)
  and not cmdArg instanceof StringLiteral
select
  cie.getLocation().getFile().getRelativePath() as file,
  cie.getLocation().getStartLine()              as line,
  cmdArg.toString()                             as command_source,
  cie.getEnclosingCallable().getName()                     as method_name,
  cie.getEnclosingCallable().getDeclaringType().getName()  as class_name
