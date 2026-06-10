# 路径遍历判断知识

## 查询结果说明

| 文件 | 含义 |
|------|------|
| `file_ops.json` | 所有文件读写、删除、复制操作 |
| `path_taint.json` | 文件操作路径参数来自用户可控输入的污点路径 |
| `path_canonical.json` | 路径规范化检查（normalize 不等于安全） |
| `zip_slip.json` | ZipEntry 名称未校验直接用于文件写入 |

## 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 用户输入直接作为文件路径 + 无规范化 | **漏洞** | HIGH |
| 有 normalize 但未校验前缀/根目录 | **漏洞** | MEDIUM |
| Zip 解压条目名未校验直接写入 | **漏洞** | HIGH（Zip Slip） |
| 路径拼接有黑名单过滤（可被编码绕过） | **漏洞** | MEDIUM |
| 有 getCanonicalPath + 前缀白名单 | **安全** | — |
| 文件路径完全硬编码 | **安全** | — |

**注意**：`../` 有多种编码绕过方式：URL 编码（`%2e%2e%2f`）、Unicode、双编码（`%252e%252e%252f`）。

`rule_id` 命名：`pathtrav-taint`、`pathtrav-no-canon`、`pathtrav-zipslip`。

**build-mode=none 限制**：Sink 参数为非字面量表达式即可上报，不要因缺少完整 Source→Sink 路径而拒绝上报。
