/**
 * 检测代码中是否通过 @Value / @ConfigurationProperties / 字符串常量
 * 将 management.endpoints.web.exposure.include 设置为 * 或 "all"。
 *
 * 这意味着所有 Actuator 端点（含 /env、/heapdump、/shutdown）都被暴露。
 */
import java

from StringLiteral s
where
  (
    s.getLiteral().matches("%management.endpoints.web.exposure.include%")
    or s.getLiteral().matches("%management.endpoint%enabled%")
  )
select
  s.getLocation().getFile().getRelativePath() as file,
  s.getLocation().getStartLine()              as line,
  s.getLiteral()                              as config_value,
  "Actuator 端点暴露配置"                      as message
