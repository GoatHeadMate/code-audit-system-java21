# CRLF 注入判断知识

CRLF 注入：攻击者在 HTTP 响应头值中注入 `\r\n`，导致 HTTP 响应分割或响应头注入。

## 查询结果说明

| 文件 | 含义 |
|------|------|
| `response_header.json` | 所有写入 HTTP 响应头的代码位置 |
| `header_taint.json` | 用户输入流向响应头写入的污点路径 |

## 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入 → addHeader/setHeader 无 CRLF 过滤 | **漏洞** | HIGH |
| 用户输入 → sendRedirect（Spring 老版本） | **漏洞** | MEDIUM |
| 框架自动过滤或有手动 CRLF 净化 | **安全** | — |

Spring Framework 5.1.1+ 对 `sendRedirect` 自动过滤 CRLF，需判断版本。

`rule_id` 命名：`crlf-header`、`crlf-redirect`。

**build-mode=none 限制**：Sink 参数为非字面量表达式即可上报。
