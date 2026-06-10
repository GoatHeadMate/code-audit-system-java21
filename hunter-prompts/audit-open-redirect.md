# 开放重定向判断知识

攻击者通过控制重定向 URL 参数将用户导向恶意站点，用于钓鱼攻击。

## 查询结果说明

| 文件 | 含义 |
|------|------|
| `redirect_sinks.json` | 所有重定向写入位置 |
| `redirect_taint.json` | 用户输入流向重定向目标的污点路径 |

## 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入 → sendRedirect 无域名验证 | **漏洞** | MEDIUM |
| return "redirect:" + 用户输入（无验证） | **漏洞** | MEDIUM |
| 有严格域名白名单 | **安全** | — |
| 仅允许相对路径且无 `//` 绕过 | **安全** | — |

注意 `//evil.com` 形式可绕过仅以 `/` 开头的相对路径限制。

`rule_id` 命名：`open-redirect-taint`、`open-redirect-unvalidated`。

**build-mode=none 限制**：Sink 参数为非字面量表达式即可上报。
