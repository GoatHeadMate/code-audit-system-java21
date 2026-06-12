# 代码执行（命令注入 + 模板注入）判断知识

本类别覆盖两类 RCE 路径：OS 命令执行和表达式/模板引擎执行。

---

## A. 命令注入判断规则

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

### 命令注入验证要点

- 沿候选路径逐步检查：入口参数是否被拼接到命令字符串中
- 检查中间环节是否存在有效净化（白名单校验、参数化执行）
- 确认调用链中的方法分派是否可达（接口实现、条件分支）

`rule_id` 命名：`cmdinj-exec-string`、`cmdinj-exec-args`、`cmdinj-procbuilder`、`cmdinj-bash-concat`、`cmdinj-template-replace`、`cmdinj-config-template`。

---

## B. SSTI（服务端模板注入）判断规则

Java 中高危场景：
- **MVEL 注入**：`MVEL.eval()`、`MVEL.executeExpression()` 或攻击者可控的编译表达式执行
- **SpEL 注入**：`parser.parseExpression(userInput).getValue()` — 可 RCE
- **FreeMarker 注入**：`Template.process(userInput, ...)` — 可调用反射
- **Velocity 注入**：`Velocity.evaluate(ctx, writer, tag, userInput)` — 可 RCE
- **Thymeleaf 片段注入**：`~{userInput}`（CVE-2021-43466）
- **OGNL 注入**：`Ognl.getValue(userInput, ctx)` — Struts2 RCE 根源

### SSTI 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入 → SpEL `parseExpression()` | **漏洞** | CRITICAL |
| HTTP 写入表达式字段 → 数据库存储 → 定时任务/消息消费读取并执行 MVEL/SpEL/Groovy | **漏洞** | CRITICAL |
| 用户输入作为 FreeMarker/Velocity 模板内容 | **漏洞** | CRITICAL |
| 用户输入仅作为模板变量（数据） | 安全 | — |
| 使用固定模板名称加载 | 安全 | — |

### SSTI 存储型候选验证要点

存储型候选（stored candidate）是本类别的核心场景：
- 确认 HTTP 写入路径中的字段与执行路径中读取的字段是同一个实体属性
- 仅 Repository 名称相同不够——必须确认字段/列对应关系
- 确认执行路径是自动触发的（`@Scheduled`、消息监听、事件处理）还是需要另一个 HTTP 请求触发
- 检查表达式引擎的 compile/bind/concatenation 步骤：值是否控制可执行语法而非仅数据变量

`rule_id` 命名：`ssti-spel`、`ssti-mvel`、`ssti-freemarker`、`ssti-velocity`、`ssti-ognl`。
