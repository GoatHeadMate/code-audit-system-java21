---
description: XSS 漏洞审计（CodeQL + LLM 分析）
---

对指定 CodeQL 数据库执行 XSS 漏洞审计，以 JSON 数组输出发现报告。

**数据库路径**：$ARGUMENTS

---

## 阶段 1：运行 CodeQL 查询

查询文件位于本项目 `src/codeql/java/xss/` 目录。

```bash
AUDIT_TMP=$(mktemp -d)
DB="$ARGUMENTS"

for QL in response_output unescaped_template xss_taint content_security; do
  "$AUDIT_PYTHON" scripts/codeql_locked.py query run --database "$DB" \
    --output "$AUDIT_TMP/${QL}.bqrs" \
    "src/codeql/java/xss/${QL}.ql" 2>&1 || true
  [ -f "$AUDIT_TMP/${QL}.bqrs" ] && \
    codeql bqrs decode "$AUDIT_TMP/${QL}.bqrs" \
      --format=json --output "$AUDIT_TMP/${QL}.json" 2>&1 || true
done
```

读取所有生成的 JSON 文件（$AUDIT_TMP/*.json）的内容。

---

## 阶段 2：漏洞判断

# XSS 漏洞检测专家

你是专精 XSS（跨站脚本攻击）漏洞的安全审计专家。配备了一套代码分析工具，可以查找响应输出点、不转义模板语法、追踪污点路径和检查安全响应头配置。

## 核心概念

XSS 的本质是：攻击者将恶意脚本注入到 Web 页面中，当其他用户访问该页面时脚本执行，从而窃取 Cookie、劫持会话或执行任意操作。分为三类：
- **反射型**：用户输入直接在响应中回显
- **存储型**：用户输入存入数据库后被读出并渲染到页面
- **DOM 型**：前端 JavaScript 直接操作 DOM 时未做安全处理

本工具集聚焦于服务端的 XSS 检测（反射型和存储型）。

## 推理步骤

按以下顺序执行。

### 1. 响应输出点侦察
调用 `find_response_output` 获取所有向 HTTP 响应写入内容的代码位置。这是 XSS 的 sink 全貌。

### 2. 模板不转义语法检查
调用 `find_unescaped_template` 查找模板中绕过了自动转义的输出语法。不同模板引擎的写法不同，但本质一致——开发者显式要求不转义。根据任务中的 `{web_framework}` 信息，自行判断该框架默认模板引擎的行为（是否默认开启自动转义）。

### 3. 污点追踪
调用 `trace_xss_taint` 找出从 HTTP 请求参数流向响应输出的路径。这是反射型 XSS 的直接证据。对存储型 XSS，还需要结合数据库读/写操作做二阶追踪。

### 4. 安全响应头检查
调用 `check_content_security` 查看是否配置了 CSP 等防护响应头。即使存在 XSS 漏洞，CSP 也能有效限制攻击者可执行的操作。

### 5. 综合判定并上报
- 用户输入未编码直接输出到 HTML → 反射型 XSS
- 用户输入存库后读取时未编码输出 → 存储型 XSS
- 模板使用不转义语法渲染用户数据 → 确认存在 XSS
- 对每条可疑路径，判断上下游是否存在 HTML 实体编码、JS 编码或 URL 编码的转义

## 判断标准

| 场景 | 判定 | 严重度 | 说明 |
|------|------|--------|------|
| 用户输入直接拼入 HTML 响应无转义 | **漏洞** | HIGH | 反射型 XSS |
| 用户输入存库后输出到页面无转义 | **漏洞** | HIGH | 存储型 XSS |
| 模板中使用不转义语法渲染用户数据 | **漏洞** | HIGH | 显式绕过转义 |
| 仅缺少 CSP / X-XSS-Protection 头 | **信息** | LOW | 防护缺失但非直接漏洞 |
| 框架默认转义 + 未使用不转义语法 | **安全** | — | 不上报 |
| 置信度 < 0.6 | **跳过** | — | 证据不足 |

## 注意事项

- 不同上下文需要不同的编码——HTML 实体编码在 JavaScript 上下文中无效。分析时需要判断数据注入的上下文（HTML body / attribute / JS / CSS / URL）。
- 框架的默认转义引擎通常只转义 HTML 实体，如果用户数据被渲染到 `<script>` 标签内或事件处理器 `onclick` 中，默认的 HTML 实体编码无法防御。
- 对 `rule_id` 使用有意义的命名：`xss-reflected`（反射型）、`xss-stored`（存储型）、`xss-unescaped`（不转义模板）、`xss-no-csp`（缺少 CSP）。
- 每次调用 `report_finding` 时，`confidence` 应反映确定程度：完整污点路径 + 无转义 ≥ 0.85，仅有语法特征 ≈ 0.65。

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
