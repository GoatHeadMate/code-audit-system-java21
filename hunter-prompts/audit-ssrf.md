# SSRF 判断知识

## 查询结果说明

| 文件 | 含义 |
|------|------|
| `outbound_http.json` | 所有对外 HTTP 请求点（RestTemplate、HttpClient、OkHttp 等） |
| `url_taint.json` | 用户输入流向 URL 构造或 HTTP 请求的污点路径（直接确认漏洞） |
| `url_validation.json` | 对目标 URL 的白名单校验或内网 IP 过滤逻辑 |
| `redirect_follow.json` | 自动跟随重定向的配置（可绕过白名单） |
| `contains_whitelist.json` | String.contains() 进行 URL 白名单校验的弱模式（可被绕过） |
| `proxy_forwarder.json` | 自定义 HTTP 代理转发模式 |

## 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户可控完整 URL + 无任何过滤 | 漏洞 | CRITICAL |
| 用户可控 URL + 仅 contains() 子串白名单 | 漏洞 | HIGH（可绕过） |
| 有白名单但开启重定向跟随 | 漏洞 | MEDIUM（重定向可绕过白名单） |
| URL 部分可控（路径/参数片段） | 漏洞 | MEDIUM |
| 有严格白名单且无重定向跟随 | 安全 | 不上报 |
| URL 硬编码 | 安全 | 不上报 |

**重点场景**：文件导入（URL 导入）、Webhook 回调、图片代理、PDF 生成。
检查是否支持 `file://` / `gopher://` / `dict://` 等非 HTTP 协议。

**综合判断**：
- 有完整污点路径 + contains() 弱过滤 → **HIGH**（confidence ≈ 0.80）
- 有完整污点路径 + 无任何过滤 → **CRITICAL**（confidence ≥ 0.90）
- 无完整路径但 outbound_http 显示 URL 参数来自外部 → **MEDIUM**（confidence ≈ 0.65）

`rule_id` 命名：`ssrf-taint`、`ssrf-no-filter`、`ssrf-weak-contains`、`ssrf-redirect`、`ssrf-proxy`。

**build-mode=none 限制**：Sink 参数为非字面量表达式即可上报，不要因缺少完整 Source→Sink 路径而拒绝上报。
