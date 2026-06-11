# 文件上传漏洞判断知识

核心风险：攻击者上传可执行文件（WebShell）到服务器可访问目录，进而执行任意代码。

## 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 无任何文件类型校验 | **漏洞** | HIGH |
| 仅有 MIME 校验，无扩展名校验 | **漏洞** | MEDIUM（MIME 可伪造） |
| 仅有黑名单校验，未使用白名单 | **漏洞** | MEDIUM |
| 写入路径在 Web 根目录下 | **漏洞** | HIGH |
| 文件名直接使用用户输入未净化 | **漏洞** | MEDIUM |
| 三维校验齐全（白名单扩展名 + 内容检测 + 安全路径）| 安全 | — |

## 验证要点

- 候选路径的入口通常是 `MultipartFile` 参数或 `@RequestPart`
- 沿调用链检查：扩展名校验、MIME 校验、文件内容检测（magic bytes）
- 检查文件写入的目标路径是否在 Web 可访问目录下
- 大小写变体（`.JSP`）、双扩展名（`.jpg.jsp`）可绕过黑名单
- 仅靠前端 JavaScript 校验无效
- 检查 `getOriginalFilename()` 是否被直接用于路径拼接（同时有路径遍历风险）

`rule_id` 命名：`upload-no-validation`、`upload-mime-only`、`upload-web-root`、`upload-path-traversal`。
