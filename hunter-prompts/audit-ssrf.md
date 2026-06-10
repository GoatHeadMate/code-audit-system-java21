---
description: SSRF 漏洞审计（CodeQL + LLM 分析）
---

对指定 CodeQL 数据库执行 SSRF（服务端请求伪造）漏洞审计，以 JSON 数组输出发现报告。

**数据库路径**：$ARGUMENTS

---

## 阶段 1：运行所有 CodeQL 查询

查询文件位于本项目 `src/codeql/java/ssrf/` 目录。

```bash
AUDIT_TMP=$(mktemp -d)
DB="$ARGUMENTS"

for QL in outbound_http url_taint url_validation redirect_follow contains_whitelist proxy_forwarder; do
  "$AUDIT_PYTHON" scripts/codeql_locked.py query run --database "$DB" \
    --output "$AUDIT_TMP/${QL}.bqrs" \
    "src/codeql/java/ssrf/${QL}.ql" 2>&1 || true
  [ -f "$AUDIT_TMP/${QL}.bqrs" ] && \
    codeql bqrs decode "$AUDIT_TMP/${QL}.bqrs" \
      --format=json --output "$AUDIT_TMP/${QL}.json" 2>&1 || true
done
```

读取所有生成的 JSON 文件内容。

---

## 阶段 2：漏洞判断

你是专精 SSRF 漏洞的安全审计专家。SSRF 的本质是攻击者通过控制服务端发起的 HTTP 请求的目标 URL，
使服务端访问本不应暴露的内部资源（云元数据、内网服务、本地文件等）。

### 查询结果说明

| 文件 | 含义 |
|------|------|
| `outbound_http.json` | 所有对外 HTTP 请求点（RestTemplate、HttpClient、OkHttp 等） |
| `url_taint.json` | 用户输入流向 URL 构造或 HTTP 请求的污点路径（直接确认漏洞） |
| `url_validation.json` | 对目标 URL 的白名单校验或内网 IP 过滤逻辑 |
| `redirect_follow.json` | 自动跟随重定向的配置（可绕过白名单） |
| `contains_whitelist.json` | String.contains() 进行 URL 白名单校验的弱模式（可被绕过） |
| `proxy_forwarder.json` | 自定义 HTTP 代理转发模式 |

### 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户可控完整 URL + 无任何过滤 | 漏洞 | CRITICAL |
| 用户可控 URL + 仅 contains() 子串白名单 | 漏洞 | HIGH（可绕过） |
| 有白名单但开启重定向跟随 | 漏洞 | MEDIUM（重定向可绕过白名单） |
| URL 部分可控（路径/参数片段） | 漏洞 | MEDIUM |
| 有严格白名单且无重定向跟随 | 安全 | 不上报 |
| URL 硬编码 | 安全 | 不上报 |
| 置信度 < 0.6 | 跳过 | — |

**重点场景**：文件导入（URL 导入）、Webhook 回调、图片代理、PDF 生成——这些均可触发出站请求。
检查是否支持 `file://` / `gopher://` / `dict://` 等非 HTTP 协议。

**url_taint.json 结合 url_validation.json / contains_whitelist.json 综合判断**：
- 有完整污点路径 + contains() 弱过滤 → **HIGH**（confidence ≈ 0.80），因为 contains 子串可绕过
- 有完整污点路径 + 无任何过滤 → **CRITICAL**（confidence ≥ 0.90）
- 无完整路径但 outbound_http 显示 URL 参数来自外部 → **MEDIUM**（confidence ≈ 0.65）

**build-mode=none 限制**：Sink 参数为非字面量表达式即可上报，不要因为缺少完整 Source→Sink 路径而拒绝上报。

---

## 阶段 3：输出报告

以 JSON 数组格式输出所有发现，无发现时输出 `[]`。

```json
[
  {
    "rule_id": "ssrf-taint",
    "title": "SSRF - 用户可控 URL 直接发起外部请求",
    "severity": "CRITICAL",
    "confidence": 0.90,
    "file": "src/main/java/com/example/ProxyController.java",
    "line": 67,
    "description": "HTTP 请求参数 targetUrl 未经过滤直接传入 RestTemplate.getForObject()。",
    "evidence": "url_taint.json: source=@RequestParam(targetUrl), sink=restTemplate.getForObject(url)"
  }
]
```

`rule_id` 参考命名：`ssrf-taint`、`ssrf-no-filter`、`ssrf-weak-contains`、`ssrf-redirect`、`ssrf-proxy`。

输出时**只输出 JSON 数组**，不要添加其他说明文字。
