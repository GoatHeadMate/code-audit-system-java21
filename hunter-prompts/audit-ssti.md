# SSTI（服务端模板注入）判断知识

Java 中高危场景：
- **MVEL 注入**：`MVEL.eval()`、`MVEL.executeExpression()` 或攻击者可控的编译表达式执行
- **SpEL 注入**：`parser.parseExpression(userInput).getValue()` — 可 RCE
- **FreeMarker 注入**：`Template.process(userInput, ...)` — 可调用反射
- **Velocity 注入**：`Velocity.evaluate(ctx, writer, tag, userInput)` — 可 RCE
- **Thymeleaf 片段注入**：`~{userInput}`（CVE-2021-43466）
- **OGNL 注入**：`Ognl.getValue(userInput, ctx)` — Struts2 RCE 根源

## 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入 → SpEL `parseExpression()` | **漏洞** | CRITICAL |
| HTTP 写入表达式字段 → 数据库存储 → 定时任务/消息消费读取并执行 MVEL/SpEL/Groovy | **漏洞** | CRITICAL |
| 用户输入作为 FreeMarker/Velocity 模板内容 | **漏洞** | CRITICAL |
| 用户输入仅作为模板变量（数据） | 安全 | — |
| 使用固定模板名称加载 | 安全 | — |

## 存储型候选验证要点

存储型候选（stored candidate）是本类别的核心场景：
- 确认 HTTP 写入路径中的字段与执行路径中读取的字段是同一个实体属性
- 仅 Repository 名称相同不够——必须确认字段/列对应关系
- 确认执行路径是自动触发的（`@Scheduled`、消息监听、事件处理）还是需要另一个 HTTP 请求触发
- 检查表达式引擎的 compile/bind/concatenation 步骤：值是否控制可执行语法而非仅数据变量

`rule_id` 命名：`ssti-spel`、`ssti-mvel`、`ssti-freemarker`、`ssti-velocity`、`ssti-ognl`。
