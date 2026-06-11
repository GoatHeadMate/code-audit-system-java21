# CRLF 注入判断知识

CRLF 注入：攻击者在 HTTP 响应头值中注入 `\r\n`，导致 HTTP 响应分割或响应头注入。

## 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入 → `addHeader`/`setHeader` 无 CRLF 过滤 | **漏洞** | HIGH |
| 用户输入 → `sendRedirect`（Spring Framework < 5.1.1） | **漏洞** | MEDIUM |
| 框架自动过滤或有手动 CRLF 净化 | 安全 | — |

## 验证要点

- 沿候选路径检查 HTTP_HEADER_WRITE sink：入口参数是否未经 CRLF 过滤直接写入响应头
- Spring Framework 5.1.1+ 对 `sendRedirect` 自动过滤 CRLF——检查 tech_profile 中的 Spring 版本
- 用 Grep 搜索响应头写入代码附近的 `\r\n` / `%0d%0a` 过滤逻辑
- Servlet 容器（Tomcat 9+）本身也会过滤头值中的换行——但不应依赖

`rule_id` 命名：`crlf-header`、`crlf-redirect`。
