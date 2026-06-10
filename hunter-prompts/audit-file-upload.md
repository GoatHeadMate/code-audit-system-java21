# 文件上传漏洞判断知识

核心风险：攻击者上传可执行文件（WebShell）到服务器可访问目录，进而执行任意代码。

## 查询结果说明

| 文件 | 含义 |
|------|------|
| `upload_endpoints.json` | 所有文件上传接口 |
| `extension_check.json` | 对原始文件名的扩展名校验代码 |
| `mime_check.json` | Content-Type 校验代码（MIME 可伪造） |
| `upload_path.json` | 文件写入的目标路径 |

## 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 无任何文件类型校验 | **漏洞** | HIGH |
| 仅有 MIME 校验，无扩展名校验 | **漏洞** | MEDIUM |
| 仅有黑名单校验，未使用白名单 | **漏洞** | MEDIUM |
| 写入路径在 Web 根目录下 | **漏洞** | HIGH |
| 文件名直接使用用户输入未净化 | **漏洞** | MEDIUM |
| 三维校验齐全且写入路径安全 | **安全** | — |

**注意**：仅靠前端 JavaScript 校验无效。需关注大小写变体、双扩展名（.jpg.jsp）绕过。

`rule_id` 命名：`upload-no-validation`、`upload-mime-only`、`upload-web-root`、`upload-path-traversal`。

**build-mode=none 限制**：Sink 参数为非字面量表达式即可上报。
