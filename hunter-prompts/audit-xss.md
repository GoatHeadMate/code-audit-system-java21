# XSS 判断知识

## 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入直接拼入 HTML 响应无转义 | **漏洞** | HIGH（反射型） |
| 用户输入存库后输出到页面无转义 | **漏洞** | HIGH（存储型） |
| 模板中使用不转义语法渲染用户数据 | **漏洞** | HIGH |
| 仅缺少 CSP / X-XSS-Protection 头 | **信息** | LOW |
| 框架默认转义 + 未使用不转义语法 | 安全 | — |

**不转义语法参考**：
- Thymeleaf: `th:utext` (unescaped) vs `th:text` (escaped)
- JSP: `<%= %>` (unescaped) vs `<c:out>` (escaped)
- FreeMarker: `${var?no_esc}` (unescaped)

**上下文注意**：HTML 实体编码在 JavaScript 上下文中无效。数据注入到 `<script>` 标签或 `onclick` 属性中时，HTML 转义无法防御，需要 JavaScript 编码。

## 验证要点

- 沿候选路径检查：入口参数是否经过 HTML 编码后输出到响应
- 检查 `HttpServletResponse.getWriter().write()` 等 HTTP_RESPONSE_WRITE sink 处的上下文
- 用 Grep 搜索对应模板文件中的不转义语法
- 检查全局 XSS 过滤器（Filter 或 Interceptor）是否覆盖该路径

`rule_id` 命名：`xss-reflected`、`xss-stored`、`xss-unescaped`、`xss-no-csp`。
