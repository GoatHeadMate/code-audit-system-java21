# 路径遍历判断知识

## 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入直接作为文件路径 + 无规范化 | **漏洞** | HIGH |
| 有 `normalize()` 但未校验前缀/根目录 | **漏洞** | MEDIUM |
| Zip 解压条目名未校验直接写入 | **漏洞** | HIGH（Zip Slip） |
| 路径拼接有黑名单过滤（可被编码绕过） | **漏洞** | MEDIUM |
| 有 `getCanonicalPath()` + 前缀白名单 | 安全 | — |
| 文件路径完全硬编码 | 安全 | — |

## 验证要点

- 沿候选路径检查 FILE_WRITE sink：入口参数如何传入文件路径
- `../` 有多种编码绕过方式：URL 编码 `%2e%2e%2f`、Unicode、双编码 `%252e%252e%252f`
- `Path.normalize()` 不等于安全——必须配合前缀校验
- 注意 Zip/Tar 解压场景：`ZipEntry.getName()` 可包含 `../` 前缀
- 检查 Spring `MultipartFile.getOriginalFilename()` 是否被直接用于文件写入路径

`rule_id` 命名：`pathtrav-taint`、`pathtrav-no-canon`、`pathtrav-zipslip`。
