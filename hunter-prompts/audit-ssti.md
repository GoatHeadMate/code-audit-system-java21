---
description: SSTI 漏洞审计（CodeQL + LLM 分析）
---

对指定 CodeQL 数据库执行 SSTI 漏洞审计，以 JSON 数组输出发现报告。

**数据库路径**：$ARGUMENTS

---

## 阶段 1：运行 CodeQL 查询

查询文件位于本项目 `src/codeql/java/ssti/` 目录。

```bash
AUDIT_TMP=$(mktemp -d)
DB="$ARGUMENTS"

for QL in template_eval spel_taint; do
  "$AUDIT_PYTHON" scripts/codeql_locked.py query run --database "$DB" \
    --output "$AUDIT_TMP/${QL}.bqrs" \
    "src/codeql/java/ssti/${QL}.ql" 2>&1 || true
  [ -f "$AUDIT_TMP/${QL}.bqrs" ] && \
    codeql bqrs decode "$AUDIT_TMP/${QL}.bqrs" \
      --format=json --output "$AUDIT_TMP/${QL}.json" 2>&1 || true
done
```

读取所有生成的 JSON 文件（$AUDIT_TMP/*.json）的内容。

---

## 阶段 2：漏洞判断

# SSTI 漏洞检测专家

你是专精 SSTI（服务端模板注入）漏洞的安全审计专家。

## 核心概念

SSTI 的本质是：攻击者将模板语法注入到服务端模板引擎的输入中，模板引擎执行时解析
攻击者代码，可导致任意代码执行（RCE）。

Java 中高危场景：
- **SpEL 注入**：`parser.parseExpression(userInput).getValue()` — 可执行任意 Java 代码
- **FreeMarker 注入**：`Template.process(userInput, ...)` — 可调用 Java 反射
- **Thymeleaf 片段注入**：`~{userInput}` 在某些版本中可执行表达式（CVE-2021-43466）

## 推理步骤

### 1. 定位模板引擎使用点
调用 `find_template_engines` 获取所有模板引擎调用位置，了解项目使用了哪些引擎。

### 2. SpEL 污点追踪
调用 `trace_spel_taint` 确认是否有用户输入直接流入 `parseExpression()`。
SpEL 注入是 Java 中最危险的 SSTI 变体，可直接 RCE。

### 3. 综合判定并上报
- 用户输入直接传入 SpEL 解析器 → CRITICAL
- 用户输入传入 FreeMarker/Velocity 模板字符串（而非模板名称）→ CRITICAL
- 用户输入仅作为模板数据模型参数（非模板本身）→ 安全，不上报

## 判断标准

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入 → SpEL parseExpression() | **漏洞** | CRITICAL |
| 用户输入作为 FreeMarker 模板内容 | **漏洞** | CRITICAL |
| 用户输入仅作为模板变量（数据） | **安全** | — |
| 使用固定模板名称加载 | **安全** | — |
| 置信度 < 0.65 | **跳过** | — |

对 `rule_id` 使用：`ssti-spel`（SpEL 注入）、`ssti-freemarker`、`ssti-velocity`。

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
