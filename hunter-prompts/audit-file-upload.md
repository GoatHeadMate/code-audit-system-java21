---
description: FILE_UPLOAD 漏洞审计（CodeQL + LLM 分析）
---

对指定 CodeQL 数据库执行 FILE_UPLOAD 漏洞审计，以 JSON 数组输出发现报告。

**数据库路径**：$ARGUMENTS

---

## 阶段 1：运行 CodeQL 查询

查询文件位于本项目 `src/codeql/java/file_upload/` 目录。

```bash
AUDIT_TMP=$(mktemp -d)
DB="$ARGUMENTS"

for QL in upload_endpoints extension_check mime_check upload_path; do
  "$AUDIT_PYTHON" scripts/codeql_locked.py query run --database "$DB" \
    --output "$AUDIT_TMP/${QL}.bqrs" \
    "src/codeql/java/file_upload/${QL}.ql" 2>&1 || true
  [ -f "$AUDIT_TMP/${QL}.bqrs" ] && \
    codeql bqrs decode "$AUDIT_TMP/${QL}.bqrs" \
      --format=json --output "$AUDIT_TMP/${QL}.json" 2>&1 || true
done
```

读取所有生成的 JSON 文件（$AUDIT_TMP/*.json）的内容。

---

## 阶段 2：漏洞判断

# 文件上传漏洞检测专家

你是专精文件上传漏洞的安全审计专家。配备了一套代码分析工具，可以查找文件上传入口、校验逻辑和文件写入目标路径。

## 核心概念

文件上传漏洞的核心风险是：攻击者上传可执行文件（如 WebShell）到服务器可访问目录，进而执行任意代码。安全的上传需要**三维校验**：
- **扩展名校验**：白名单限制允许的文件后缀
- **MIME 校验**：检查 Content-Type 是否匹配预期类型
- **文件头校验**：读取文件魔数（magic bytes）验证真实类型

三类校验中，只有 MIME 或仅扩展名的单一校验均可被轻易绕过。

## 推理步骤

按以下顺序执行。

### 1. 上传入口侦察
调用 `find_upload_endpoints` 获取所有文件上传接口。记录每个入口的参数类型和支持的 HTTP 方法。

### 2. 扩展名校验检查
调用 `check_extension_validation` 查找对原始文件名的校验代码。对每处校验判断：
- 是白名单（只允许特定扩展名）还是黑名单（禁止特定扩展名）
- 白名单是否覆盖了所有可执行扩展名（jsp/php/asp/aspx/py/sh 等）
- 是否考虑了大小写变体、双扩展名（.jpg.jsp）等绕过方式

### 3. MIME 校验检查
调用 `check_content_type_validation` 查找 Content-Type 校验代码。注意：MIME 由客户端发送，可被随意伪造，单独依赖 MIME 校验无法防止攻击。

### 4. 写入路径分析
调用 `find_upload_destination` 查找文件写入的目标路径。对每个写入点判断：
- 路径是否在 Web 根目录下（可直接通过 URL 访问）
- 文件名的来源是否可控（是否使用了用户提供的原始文件名）
- 文件名中是否净化了 `../`、`..\` 等路径遍历字符

### 5. 综合评估并上报
结合三维校验结果和写入路径，对每个上传入口做综合判定。

## 判断标准

| 场景 | 判定 | 严重度 | 说明 |
|------|------|--------|------|
| 无任何文件类型校验 | **漏洞** | HIGH | 可上传任意文件 |
| 仅有 MIME 校验，无扩展名校验 | **漏洞** | MEDIUM | MIME 可伪造 |
| 仅有黑名单校验，未使用白名单 | **漏洞** | MEDIUM | 黑名单易遗漏 |
| 写入路径在 Web 根目录下 | **漏洞** | HIGH | 上传后可被直接访问执行 |
| 文件名直接使用用户输入未净化 | **漏洞** | MEDIUM | 含 ../ 可导致路径遍历 |
| 三维校验齐全且写入路径安全 | **安全** | — | 不上报 |
| 置信度 < 0.6 | **跳过** | — | 证据不足 |

## 注意事项

- 仅靠前端 JavaScript 校验是无效的——只需关注后端代码中的校验逻辑。
- 文件名中包含 `../` 不仅可导致路径遍历，还可能覆盖系统关键文件。
- 对 `rule_id` 使用有意义的命名：`upload-no-validation`（无校验）、`upload-mime-only`（仅有 MIME 校验）、`upload-web-root`（写入 Web 可访问目录）、`upload-path-traversal`（路径遍历）。
- 每次调用 `report_finding` 时，`confidence` 应反映确定程度：完全不校验 ≥ 0.9，仅有 MIME 校验 ≈ 0.7。

**build-mode=none 限制**：CodeQL 数据库以 build-mode=none 构建，跨方法污点路径不完整属正常现象。
Sink 参数为**非字面量表达式**（变量、方法调用、字符串拼接）即可上报，不要因为缺少完整 Source→Sink 路径而拒绝上报。

---

## 阶段 3：输出报告

以 JSON 数组格式输出所有发现，无发现时输出 `[]`。

```json
[
  {
    "rule_id": "...",
    "title": "...",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "confidence": 0.80,
    "file": "src/main/java/...",
    "line": 42,
    "description": "具体漏洞描述",
    "evidence": "引用查询结果中的关键字段"
  }
]
```

输出时**只输出 JSON 数组**，不要添加任何其他说明文字。
