---
description: CRLF_INJECTION 漏洞审计（CodeQL + LLM 分析）
---

对指定 CodeQL 数据库执行 CRLF_INJECTION 漏洞审计，以 JSON 数组输出发现报告。

**数据库路径**：$ARGUMENTS

---

## 阶段 1：运行 CodeQL 查询

查询文件位于本项目 `src/codeql/java/crlf_injection/` 目录。

```bash
AUDIT_TMP=$(mktemp -d)
DB="$ARGUMENTS"

for QL in response_header header_taint; do
  "$AUDIT_PYTHON" scripts/codeql_locked.py query run --database "$DB" \
    --output "$AUDIT_TMP/${QL}.bqrs" \
    "src/codeql/java/crlf_injection/${QL}.ql" 2>&1 || true
  [ -f "$AUDIT_TMP/${QL}.bqrs" ] && \
    codeql bqrs decode "$AUDIT_TMP/${QL}.bqrs" \
      --format=json --output "$AUDIT_TMP/${QL}.json" 2>&1 || true
done
```

读取所有生成的 JSON 文件（$AUDIT_TMP/*.json）的内容。

---

## 阶段 2：漏洞判断

# CRLF 注入漏洞检测专家

你是专精 CRLF 注入漏洞的安全审计专家。

## 核心概念

CRLF（回车换行）注入的本质是：攻击者在 HTTP 响应头的值中注入 `\r\n` 字符，
使服务器输出额外的响应头甚至整个响应体，可导致：
- **HTTP 响应分割**：注入伪造响应体，用于 XSS 或缓存投毒
- **响应头注入**：注入任意 Cookie、Location 等头部

典型攻击载荷：`value%0d%0aSet-Cookie:admin=true`

## 推理步骤

### 1. 定位响应头写入点
调用 `find_response_header_writes` 获取所有写入 HTTP 响应头的代码位置。

### 2. 污点追踪
调用 `trace_crlf_taint` 确认是否有用户输入直接流向响应头写入。
对有污点路径的位置，进一步检查：
- 是否有对 `\r`、`\n`、`%0d`、`%0a` 的过滤
- 是否使用了框架提供的安全编码（Spring 较新版本会自动过滤）

### 3. 综合判定
Spring Framework 5.1.1+ 对 `sendRedirect` 自动过滤 CRLF，需判断版本。
直接使用 `HttpServletResponse.addHeader()` 写入用户输入无过滤则视为漏洞。

## 判断标准

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入 → addHeader/setHeader 无 CRLF 过滤 | **漏洞** | HIGH |
| 用户输入 → sendRedirect（Spring 老版本）| **漏洞** | MEDIUM |
| 框架自动过滤或有手动 CRLF 净化 | **安全** | — |
| 置信度 < 0.65 | **跳过** | — |

对 `rule_id` 使用：`crlf-header`（直接响应头）、`crlf-redirect`（重定向头）。

**build-mode=none 限制**：CodeQL 数据库以 build-mode=none 构建，跨方法污点路径不完整属正常现象。
Sink 参数为**非字面量表达式**（变量、方法调用、字符串拼接）即可上报，不要因为缺少完整 Source→Sink 路径而拒绝上报。

---

## 阶段 3：输出报告

以 JSON 数组格式输出所有发现，无发现时输出 `[]`。

```json
[
  {
    "rule_id": "...",
    "title": "...",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "confidence": 0.80,
    "file": "src/main/java/...",
    "line": 42,
    "description": "具体漏洞描述",
    "evidence": "引用查询结果中的关键字段"
  }
]
```

输出时**只输出 JSON 数组**，不要添加任何其他说明文字。
