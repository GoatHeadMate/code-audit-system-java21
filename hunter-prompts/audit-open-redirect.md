# 开放重定向判断知识

攻击者通过控制重定向 URL 参数将用户导向恶意站点，用于钓鱼攻击。

## 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入 → `sendRedirect` 无域名验证 | **漏洞** | MEDIUM |
| `return "redirect:" + userInput`（无验证） | **漏洞** | MEDIUM |
| 有严格域名白名单 | 安全 | — |
| 仅允许相对路径且无 `//` 绕过 | 安全 | — |

## 验证要点

- 沿候选路径检查 HTTP_REDIRECT sink：入口参数是否直接用于重定向目标
- `//evil.com` 可绕过仅以 `/` 开头的相对路径限制
- `@RequestParam("returnUrl")` + `sendRedirect(returnUrl)` 是最常见模式
- 检查是否有域名白名单校验、`URL` 对象解析、正则匹配等防护
- 登录后跳转（`/login?redirect=`）是高频出现场景

`rule_id` 命名：`open-redirect-taint`、`open-redirect-unvalidated`。
