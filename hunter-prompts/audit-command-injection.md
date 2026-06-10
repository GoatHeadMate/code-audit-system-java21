# 命令注入判断知识

## 查询结果说明

| 文件 | 含义 |
|------|------|
| `runtime_exec.json` | Runtime.exec() 调用，注意 `is_string_form` 字段 |
| `process_builder.json` | ProcessBuilder 使用，注意 `command_source` 字段 |
| `cmd_taint.json` | HTTP 输入 → 命令执行的污点路径（直接确认漏洞） |
| `cmd_sanitize.json` | 命令执行前的输入过滤逻辑 |
| `bash_concat_injection.json` | bash/sh -c + 动态拼接参数模式 |
| `string_replace_to_exec.json` | String.replace("${...}", value) 模板替换模式 |

## 判断规则

**① cmd_taint 有路径（最强证据）**
- `exec(String)` 形式或 `is_string_form=true` → **CRITICAL**，confidence ≥ 0.90
- 数组形式 / ProcessBuilder 且整个命令可控 → **HIGH**，confidence ≈ 0.85

**② runtime_exec / process_builder 有结果，但 taint 无路径**
- `command_source` 含 RequestParam / PathVariable / RequestBody → **HIGH**，confidence ≈ 0.75
- 命令已硬编码或来自系统配置 → 安全，跳过
- 反序列化 gadget 类中的 exec → **MEDIUM**，confidence ≈ 0.65

**③ bash_concat_injection 有结果**
- ProcessBuilder 以 bash/sh -c 执行，第三参数为变量/拼接表达式 → **HIGH**，confidence ≈ 0.80
- 来自 HTTP 入口的变量 → **CRITICAL**

**④ string_replace_to_exec 有结果**
- 模板替换后传入 exec 且值来自外部输入 → **HIGH**，confidence ≈ 0.75

**⑤ cmd_sanitize 过滤器降级**
- 严格白名单（仅允许特定命令集合）→ 安全，不上报
- 黑名单过滤或字符过滤不完整 → 降一级（CRITICAL→HIGH，HIGH→MEDIUM）

`rule_id` 命名：`cmdinj-exec-string`、`cmdinj-exec-args`、`cmdinj-procbuilder`、`cmdinj-bash-concat`、`cmdinj-template-replace`。

**build-mode=none 限制**：Sink 参数为非字面量表达式即可上报，不要因缺少完整 Source→Sink 路径而拒绝上报。
