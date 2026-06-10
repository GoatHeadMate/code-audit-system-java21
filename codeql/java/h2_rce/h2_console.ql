/**
 * 检测 H2 数据库控制台暴露风险。
 *
 * 覆盖场景：
 *   1. @Value 或 @ConfigurationProperties 中包含 h2-console / h2.console.enabled 配置
 *   2. Java 代码中显式启用 H2 console 的 setter 调用
 *   3. 字符串常量中出现 h2-console URL 路径
 */
import java

/** 包含 H2 console 配置关键字的字符串字面量 */
class H2ConsoleConfigLiteral extends StringLiteral {
  H2ConsoleConfigLiteral() {
    this.getLiteral().toLowerCase().matches("%h2-console%")
    or this.getLiteral().toLowerCase().matches("%h2.console.enabled%")
    or this.getLiteral().toLowerCase().matches("%h2.console.path%")
  }
}

/** H2ConsoleProperties.setEnabled(true) 调用 */
class H2ConsoleEnabledCall extends MethodCall {
  H2ConsoleEnabledCall() {
    this.getMethod().getDeclaringType().getName().matches("%H2Console%")
    and this.getMethod().hasName("setEnabled")
  }
}

from Top t, string detail
where
  (
    t instanceof H2ConsoleConfigLiteral
    and detail = "字符串常量引用 H2 Console 配置：" + t.(H2ConsoleConfigLiteral).getLiteral()
  )
  or
  (
    t instanceof H2ConsoleEnabledCall
    and detail = "显式调用 H2ConsoleProperties.setEnabled()"
  )
select
  t.getLocation().getFile().getRelativePath() as file,
  t.getLocation().getStartLine()              as line,
  detail                                      as message
