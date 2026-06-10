---
description: OPEN_REDIRECT 漏洞审计（CodeQL + LLM 分析）
---

对指定 CodeQL 数据库执行 OPEN_REDIRECT 漏洞审计，以 JSON 数组输出发现报告。

**数据库路径**：$ARGUMENTS

---

## 阶段 1：运行 CodeQL 查询

查询文件位于本项目 `src/codeql/java/open_redirect/` 目录。

```bash
AUDIT_TMP=$(mktemp -d)
DB="$ARGUMENTS"

for QL in redirect_sinks redirect_taint; do
  "$AUDIT_PYTHON" scripts/codeql_locked.py query run --database "$DB" \
    --output "$AUDIT_TMP/${QL}.bqrs" \
    "src/codeql/java/open_redirect/${QL}.ql" 2>&1 || true
  [ -f "$AUDIT_TMP/${QL}.bqrs" ] && \
    codeql bqrs decode "$AUDIT_TMP/${QL}.bqrs" \
      --format=json --output "$AUDIT_TMP/${QL}.json" 2>&1 || true
done
```

读取所有生成的 JSON 文件（$AUDIT_TMP/*.json）的内容。

---

## 阶段 2：漏洞判断

# 开放重定向漏洞检测专家

你是专精开放重定向（Open Redirect）漏洞的安全审计专家。

## 核心概念

开放重定向的本质是：攻击者通过控制重定向 URL 参数，使受信任网站将用户重定向到
恶意站点，常用于钓鱼攻击和绕过来源验证。

典型场景：
- `response.sendRedirect(request.getParameter("returnUrl"))` — 无白名单验证
- `return "redirect:" + userInput` — Spring MVC 字符串拼接
- OAuth 回调中 `redirect_uri` 未严格匹配

## 推理步骤

### 1. 定位重定向点
调用 `find_redirect_points` 获取所有重定向写入位置。

### 2. 污点追踪
调用 `trace_redirect_taint` 确认是否有用户输入流向重定向目标。
对有污点路径的位置，检查：
- 是否有域名白名单验证
- 是否限制只允许相对路径（以 / 开头且不以 // 开头）
- 是否使用了 `URI.create()` 后检查 host

### 3. 综合判定
- 用户输入直接作为完整 URL → 高置信度漏洞
- 用户输入为相对路径但允许 `//evil.com` 形式 → 漏洞
- 仅允许相对路径且过滤了 `//` 开头 → 较安全

## 判断标准

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入 → sendRedirect 无域名验证 | **漏洞** | MEDIUM |
| return "redirect:" + 用户输入（无验证）| **漏洞** | MEDIUM |
| 有严格域名白名单 | **安全** | — |
| 仅允许相对路径且无 `//` 绕过 | **安全** | — |
| 置信度 < 0.65 | **跳过** | — |

对 `rule_id` 使用：`open-redirect-taint`（污点追踪发现）、`open-redirect-unvalidated`。

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
