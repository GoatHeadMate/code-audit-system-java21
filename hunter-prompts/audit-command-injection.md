---
description: 命令注入漏洞审计（CodeQL + LLM 分析）
---

对指定 CodeQL 数据库执行命令注入漏洞审计，以 JSON 数组输出发现报告。

**数据库路径**：$ARGUMENTS

---

## 阶段 1：运行所有 CodeQL 查询

将上方数据库路径作为 `--database` 参数。先创建临时目录，然后依次运行以下 6 个查询。每个查询分两步：`codeql query run` 生成 bqrs，再用 `codeql bqrs decode` 导出 JSON。

查询文件均位于本项目 `src/codeql/java/command_injection/` 目录下。

```bash
AUDIT_TMP=$(mktemp -d)
DB="$ARGUMENTS"

for QL in runtime_exec process_builder cmd_taint cmd_sanitize bash_concat_injection string_replace_to_exec; do
  "$AUDIT_PYTHON" scripts/codeql_locked.py query run --database "$DB" \
    --output "$AUDIT_TMP/${QL}.bqrs" \
    "src/codeql/java/command_injection/${QL}.ql" 2>&1 || true
  [ -f "$AUDIT_TMP/${QL}.bqrs" ] && \
    codeql bqrs decode "$AUDIT_TMP/${QL}.bqrs" \
      --format=json --output "$AUDIT_TMP/${QL}.json" 2>&1 || true
done
```

读取所有生成的 JSON 文件内容。

---

## 阶段 2：漏洞判断

你是专精命令注入漏洞的安全审计专家。分析上方查询结果，遵循以下判断标准。

### 查询结果说明

| 文件 | 含义 |
|------|------|
| `runtime_exec.json` | Runtime.exec() 调用，注意 `is_string_form` 字段 |
| `process_builder.json` | ProcessBuilder 使用，注意 `command_source` 字段 |
| `cmd_taint.json` | HTTP 输入 → 命令执行的污点路径（直接确认漏洞） |
| `cmd_sanitize.json` | 命令执行前的输入过滤逻辑 |
| `bash_concat_injection.json` | bash/sh -c + 动态拼接参数模式 |
| `string_replace_to_exec.json` | String.replace("${...}", value) 模板替换模式 |

### 判断规则

**① cmd_taint.json 有路径（最强证据）**
- `exec(String)` 形式或 `is_string_form=true` → **CRITICAL**，confidence ≥ 0.90
- 数组形式 / ProcessBuilder 且整个命令可控 → **HIGH**，confidence ≈ 0.85

**② runtime_exec / process_builder 有结果，但 taint 无路径**
- `command_source` 含 RequestParam / PathVariable / RequestBody → **HIGH**，confidence ≈ 0.75
- 命令已硬编码或来自系统配置 → 安全，跳过
- 反序列化 gadget 类中的 exec → **MEDIUM**，confidence ≈ 0.65

**③ bash_concat_injection 有结果**
- ProcessBuilder 以 bash/sh -c 执行，第三参数（-c 后）为变量/拼接表达式 → **HIGH**，confidence ≈ 0.80
- 来自 HTTP 入口的变量 → **CRITICAL**

**④ string_replace_to_exec 有结果**
- 模板替换后传入 exec 且值来自外部输入 → **HIGH**，confidence ≈ 0.75

**⑤ cmd_sanitize 过滤器降级**
- 严格白名单（仅允许特定命令集合）→ 安全，不上报
- 黑名单过滤或字符过滤不完整 → 降一级（CRITICAL→HIGH，HIGH→MEDIUM）

**build-mode=none 限制**：CodeQL 数据库以 build-mode=none 构建，跨方法污点路径不完整属正常现象。
Sink 参数为**非字面量表达式**（变量、方法调用、字符串拼接）即可上报，不要因为没有完整 Source→Sink 路径而拒绝上报。

---

## 阶段 3：输出报告

以 JSON 数组格式输出所有发现，无发现时输出 `[]`。每个发现包含：

```json
[
  {
    "rule_id": "cmdinj-exec-string",
    "title": "命令注入 - Runtime.exec() 字符串形式",
    "severity": "CRITICAL",
    "confidence": 0.92,
    "file": "src/main/java/com/example/FooService.java",
    "line": 42,
    "description": "Runtime.exec() 以字符串形式执行命令，shell 会解析元字符；参数 cmd 来自 HTTP 请求参数。",
    "evidence": "runtime_exec.json: is_string_form=true, method=executeCommand, class=TaskController"
  }
]
```

`rule_id` 参考命名：`cmdinj-exec-string`、`cmdinj-exec-args`、`cmdinj-procbuilder`、
`cmdinj-bash-concat`、`cmdinj-template-replace`、`cmdinj-deserialization-gadget`。

输出时**只输出 JSON 数组**，不要添加其他说明文字。
