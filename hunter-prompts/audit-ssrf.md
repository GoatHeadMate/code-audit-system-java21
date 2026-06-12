# SSRF 判断知识

## 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户可控完整 URL + 无任何过滤 | **漏洞** | CRITICAL |
| 用户可控 URL + 仅 `contains()` 子串白名单 | **漏洞** | HIGH（可绕过） |
| 有白名单但开启重定向跟随 | **漏洞** | MEDIUM（重定向可绕过白名单） |
| URL 部分可控（路径/参数片段） | **漏洞** | MEDIUM |
| 有严格白名单且无重定向跟随 | 安全 | 不上报 |
| URL 硬编码 | 安全 | 不上报 |

**重点场景**：文件导入（URL 导入）、Webhook 回调、图片代理、PDF 生成。

**综合判断**：
- 候选路径显示 HTTP 参数直接流入 URL 构造 + 无过滤 → **CRITICAL**（confidence ≥ 0.90）
- 候选路径显示 HTTP 参数流入 URL + 仅 `contains()` 弱过滤 → **HIGH**（confidence ≈ 0.80）
- 候选路径到 OUTBOUND_HTTP sink 但中间经过不透明方法 → **MEDIUM**（confidence ≈ 0.65）

## 验证要点

- 检查是否支持 `file://` / `gopher://` / `dict://` 等非 HTTP 协议
- 检查 HttpClient/RestTemplate 是否配置了自动跟随重定向
- 用 Grep 搜索目标 URL 的验证逻辑（白名单、域名校验、IP 黑名单）
- `String.contains()` 白名单可被 `http://evil.com#whitelisted.com` 绕过
- **代理凭据注入**：检查 HTTP 转发/代理工具类（BackendRestClient、RestTemplate wrapper）是否在转发请求时自动添加认证头（x-user-name、Authorization、Cookie 等）。如果是，SSRF 的影响从"可发送请求"升级为"可以管理员身份发送请求"，在 finding 的 message 中标注。
- **具体绕过手法**：对 contains()/startsWith() 白名单，需给出至少一种具体绕过 payload，如 `http://internal:8080/malicious?x=/whitelisted/path` 或 `http://whitelisted.com@evil.com`

`rule_id` 命名：`ssrf-taint`、`ssrf-no-filter`、`ssrf-weak-contains`、`ssrf-redirect`、`ssrf-proxy`。
