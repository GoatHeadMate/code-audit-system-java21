# XSS 判断知识

## 查询结果说明

| 文件 | 含义 |
|------|------|
| `response_output.json` | 所有向 HTTP 响应写入内容的代码位置（sink 全貌） |
| `unescaped_template.json` | 模板中绕过自动转义的输出语法 |
| `xss_taint.json` | HTTP 请求参数流向响应输出的污点路径（直接确认反射型 XSS） |
| `content_security.json` | CSP 等防护响应头配置 |

## 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入直接拼入 HTML 响应无转义 | **漏洞** | HIGH（反射型） |
| 用户输入存库后输出到页面无转义 | **漏洞** | HIGH（存储型） |
| 模板中使用不转义语法渲染用户数据 | **漏洞** | HIGH |
| 仅缺少 CSP / X-XSS-Protection 头 | **信息** | LOW |
| 框架默认转义 + 未使用不转义语法 | **安全** | — |

**上下文注意**：HTML 实体编码在 JavaScript 上下文中无效。数据注入到 `<script>` 标签或 `onclick` 中时默认转义无法防御。

`rule_id` 命名：`xss-reflected`、`xss-stored`、`xss-unescaped`、`xss-no-csp`。

**build-mode=none 限制**：Sink 参数为非字面量表达式即可上报，不要因缺少完整 Source→Sink 路径而拒绝上报。
