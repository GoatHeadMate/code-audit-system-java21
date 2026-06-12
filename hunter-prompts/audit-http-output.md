# HTTP 输出注入（XSS + CRLF 注入 + 开放重定向）判断知识

本类别覆盖三类向 HTTP 响应注入的风险：响应体注入（XSS）、响应头注入（CRLF）、重定向目标注入（Open Redirect）。

---

## A. XSS 判断规则

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

### XSS 验证要点

- 沿候选路径检查：入口参数是否经过 HTML 编码后输出到响应
- 检查 `HttpServletResponse.getWriter().write()` 等 HTTP_RESPONSE_WRITE sink 处的上下文
- 用 Grep 搜索对应模板文件中的不转义语法
- 检查全局 XSS 过滤器（Filter 或 Interceptor）是否覆盖该路径

`rule_id` 命名：`xss-reflected`、`xss-stored`、`xss-unescaped`、`xss-no-csp`。

---

## B. CRLF 注入判断知识

CRLF 注入：攻击者在 HTTP 响应头值中注入 `\r\n`，导致 HTTP 响应分割或响应头注入。

### CRLF 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入 → `addHeader`/`setHeader` 无 CRLF 过滤 | **漏洞** | HIGH |
| 用户输入 → `sendRedirect`（Spring Framework < 5.1.1） | **漏洞** | MEDIUM |
| 框架自动过滤或有手动 CRLF 净化 | 安全 | — |

### CRLF 验证要点

- 沿候选路径检查 HTTP_HEADER_WRITE sink：入口参数是否未经 CRLF 过滤直接写入响应头
- Spring Framework 5.1.1+ 对 `sendRedirect` 自动过滤 CRLF——检查 tech_profile 中的 Spring 版本
- 用 Grep 搜索响应头写入代码附近的 `\r\n` / `%0d%0a` 过滤逻辑
- Servlet 容器（Tomcat 9+）本身也会过滤头值中的换行——但不应依赖

`rule_id` 命名：`crlf-header`、`crlf-redirect`。

---

## C. 开放重定向判断知识

攻击者通过控制重定向 URL 参数将用户导向恶意站点，用于钓鱼攻击。

### 开放重定向判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入 → `sendRedirect` 无域名验证 | **漏洞** | MEDIUM |
| `return "redirect:" + userInput`（无验证） | **漏洞** | MEDIUM |
| 有严格域名白名单 | 安全 | — |
| 仅允许相对路径且无 `//` 绕过 | 安全 | — |

### 开放重定向验证要点

- 沿候选路径检查 HTTP_REDIRECT sink：入口参数是否直接用于重定向目标
- `//evil.com` 可绕过仅以 `/` 开头的相对路径限制
- `@RequestParam("returnUrl")` + `sendRedirect(returnUrl)` 是最常见模式
- 检查是否有域名白名单校验、`URL` 对象解析、正则匹配等防护
- 登录后跳转（`/login?redirect=`）是高频出现场景

`rule_id` 命名：`open-redirect-taint`、`open-redirect-unvalidated`。
