# 命令注入判断知识

## 判断规则

**① Runtime.exec(String) 单字符串形式**
- 候选路径终点为 `Runtime.exec(String)` → **CRITICAL**，confidence ≥ 0.90
- 底层 shell 直接解析完整命令字符串，无需额外拼接即可注入

**② ProcessBuilder 或 Runtime.exec(String[]) 数组形式**
- 整个命令或第一个参数可控 → **HIGH**，confidence ≈ 0.85
- 仅后续参数部分可控 → **MEDIUM**，confidence ≈ 0.65

**③ bash/sh -c 拼接模式**
- ProcessBuilder 以 `bash -c` / `sh -c` 执行，第三参数为变量或拼接表达式 → **HIGH**，confidence ≈ 0.80
- 该参数值可追溯到 HTTP 入口 → 升级为 **CRITICAL**

**④ 模板替换后执行**
- `String.replace("${...}", value)` 后传入 exec，且 value 来自外部输入 → **HIGH**，confidence ≈ 0.75

**④-b 配置模板拼接后执行**
- YAML/properties 中定义命令模板（含 `${...}`），Java 代码用 String.replace 替换后执行 → **HIGH**，confidence ≈ 0.80
- 重点检查：TaskUtil.generateQuery() 等通用模板替换工具方法
- 需追踪模板值来源（配置文件）和替换参数来源（HTTP 输入）

**⑤ 反序列化 gadget 链中的 exec**
- 反序列化 gadget 类中的 exec → **MEDIUM**，confidence ≈ 0.65

**⑥ 降级条件**
- 严格白名单（仅允许特定命令集合）→ 安全，不上报
- 黑名单过滤或字符过滤不完整 → 降一级（CRITICAL→HIGH，HIGH→MEDIUM）

## 验证要点

- 沿候选路径逐步检查：入口参数是否被拼接到命令字符串中
- 检查中间环节是否存在有效净化（白名单校验、参数化执行）
- 确认调用链中的方法分派是否可达（接口实现、条件分支）

`rule_id` 命名：`cmdinj-exec-string`、`cmdinj-exec-args`、`cmdinj-procbuilder`、`cmdinj-bash-concat`、`cmdinj-template-replace`、`cmdinj-config-template`。
