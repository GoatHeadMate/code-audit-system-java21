# 文件操作漏洞（文件上传 + 路径遍历）判断知识

本类别覆盖两类文件系统操作的风险：恶意文件上传和路径遍历。

---

## A. 文件上传漏洞判断知识

核心风险：攻击者上传可执行文件（WebShell）到服务器可访问目录，进而执行任意代码。

### 文件上传判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 无任何文件类型校验 | **漏洞** | HIGH |
| 仅有 MIME 校验，无扩展名校验 | **漏洞** | MEDIUM（MIME 可伪造） |
| 仅有黑名单校验，未使用白名单 | **漏洞** | MEDIUM |
| 写入路径在 Web 根目录下 | **漏洞** | HIGH |
| 文件名直接使用用户输入未净化 | **漏洞** | MEDIUM |
| 三维校验齐全（白名单扩展名 + 内容检测 + 安全路径）| 安全 | — |

### 文件上传验证要点

- 候选路径的入口通常是 `MultipartFile` 参数或 `@RequestPart`
- 沿调用链检查：扩展名校验、MIME 校验、文件内容检测（magic bytes）
- 检查文件写入的目标路径是否在 Web 可访问目录下
- 大小写变体（`.JSP`）、双扩展名（`.jpg.jsp`）可绕过黑名单
- 仅靠前端 JavaScript 校验无效
- 检查 `getOriginalFilename()` 是否被直接用于路径拼接（同时有路径遍历风险）

`rule_id` 命名：`upload-no-validation`、`upload-mime-only`、`upload-web-root`、`upload-path-traversal`。

---

## B. 路径遍历判断知识

### 路径遍历判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入直接作为文件路径 + 无规范化 | **漏洞** | HIGH |
| 有 `normalize()` 但未校验前缀/根目录 | **漏洞** | MEDIUM |
| Zip 解压条目名未校验直接写入 | **漏洞** | HIGH（Zip Slip） |
| 路径拼接有黑名单过滤（可被编码绕过） | **漏洞** | MEDIUM |
| 有 `getCanonicalPath()` + 前缀白名单 | 安全 | — |
| 文件路径完全硬编码 | 安全 | — |

### 路径遍历验证要点

- 沿候选路径检查 FILE_WRITE sink：入口参数如何传入文件路径
- `../` 有多种编码绕过方式：URL 编码 `%2e%2e%2f`、Unicode、双编码 `%252e%252e%252f`
- `Path.normalize()` 不等于安全——必须配合前缀校验
- 注意 Zip/Tar 解压场景：`ZipEntry.getName()` 可包含 `../` 前缀
- 检查 Spring `MultipartFile.getOriginalFilename()` 是否被直接用于文件写入路径

`rule_id` 命名：`pathtrav-taint`、`pathtrav-no-canon`、`pathtrav-zipslip`。
