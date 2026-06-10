# SSTI（服务端模板注入）判断知识

Java 中高危场景：
- **SpEL 注入**：`parser.parseExpression(userInput).getValue()` — 可 RCE
- **FreeMarker 注入**：`Template.process(userInput, ...)` — 可调用反射
- **Thymeleaf 片段注入**：`~{userInput}`（CVE-2021-43466）

## 查询结果说明

| 文件 | 含义 |
|------|------|
| `template_eval.json` | 所有模板引擎调用位置 |
| `spel_taint.json` | 用户输入流入 SpEL parseExpression() 的污点路径 |

## 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入 → SpEL parseExpression() | **漏洞** | CRITICAL |
| 用户输入作为 FreeMarker 模板内容 | **漏洞** | CRITICAL |
| 用户输入仅作为模板变量（数据） | **安全** | — |
| 使用固定模板名称加载 | **安全** | — |

`rule_id` 命名：`ssti-spel`、`ssti-freemarker`、`ssti-velocity`。

**build-mode=none 限制**：Sink 参数为非字面量表达式即可上报。
