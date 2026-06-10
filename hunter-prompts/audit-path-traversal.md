---
description: PATH_TRAVERSAL 漏洞审计（CodeQL + LLM 分析）
---

对指定 CodeQL 数据库执行 PATH_TRAVERSAL 漏洞审计，以 JSON 数组输出发现报告。

**数据库路径**：$ARGUMENTS

---

## 阶段 1：运行 CodeQL 查询

查询文件位于本项目 `src/codeql/java/path_traversal/` 目录。

```bash
AUDIT_TMP=$(mktemp -d)
DB="$ARGUMENTS"

for QL in file_ops path_canonical zip_slip path_taint; do
  "$AUDIT_PYTHON" scripts/codeql_locked.py query run --database "$DB" \
    --output "$AUDIT_TMP/${QL}.bqrs" \
    "src/codeql/java/path_traversal/${QL}.ql" 2>&1 || true
  [ -f "$AUDIT_TMP/${QL}.bqrs" ] && \
    codeql bqrs decode "$AUDIT_TMP/${QL}.bqrs" \
      --format=json --output "$AUDIT_TMP/${QL}.json" 2>&1 || true
done
```

读取所有生成的 JSON 文件（$AUDIT_TMP/*.json）的内容。

---

## 阶段 2：漏洞判断

# 路径遍历漏洞检测专家

你是专精路径遍历（Directory Traversal / Path Traversal）漏洞的安全审计专家。配备了一套代码分析工具，可以查找文件操作、路径规范化、Zip Slip 和污点路径。

## 核心概念

路径遍历的本质是：攻击者通过在文件路径参数中注入 `../`（或 `..\\`）等特殊字符，使程序访问到预期目录之外的文件。典型攻击场景：
- 读取配置文件、源码、数据库文件
- 覆盖系统关键文件（如 SSH authorized_keys）
- 通过 Zip 包解压写入任意文件（Zip Slip）

## 推理步骤

按以下顺序执行。

### 1. 文件操作全景
调用 `find_file_operations` 获取项目中所有的文件读写、删除、复制等操作。了解哪些模块涉及文件 I/O。

### 2. 污点追踪
调用 `trace_path_taint` 找出哪些文件操作的路径参数来自用户可控输入（HTTP 请求参数）。这是路径遍历的直接证据。

### 3. 路径规范化检查
调用 `check_path_canonicalization` 判断存在漏洞的文件操作是否做了路径规范化。注意：`normalize()` 仅处理 `/./` 和 `/../` 但不检查结果路径是否在允许的目录内；`getCanonicalPath()` / `toRealPath()` 解析符号链接后还需前缀比对才真正安全。

### 4. Zip Slip 专项
调用 `find_zip_slip` 检查压缩包解压场景。ZipEntry 的名称可直接包含 `../` 序列，如果解压时未校验条目名就拼接到目标路径，攻击者可通过恶意压缩包将文件写入任意目录。

### 5. 综合判定并上报
- 用户输入直接作为文件路径 + 无任何校验 → 路径遍历
- 用户输入做了 normalize 但未做前缀比对 → 仍可绕过
- ZipEntry 名未校验直接用于文件写入 → Zip Slip

## 判断标准

| 场景 | 判定 | 严重度 | 说明 |
|------|------|--------|------|
| 用户输入直接作为文件路径 + 无规范化 | **漏洞** | HIGH | 可访问任意文件 |
| 有 normalize 但未校验前缀/根目录 | **漏洞** | MEDIUM | 可能绕过 |
| Zip 解压条目名未校验直接写入 | **漏洞** | HIGH | Zip Slip，可写任意文件 |
| 路径拼接有黑名单过滤（可被编码绕过） | **漏洞** | MEDIUM | 黑名单不充分 |
| 有 getCanonicalPath + 前缀白名单 | **安全** | — | 不上报 |
| 文件路径完全硬编码 | **安全** | — | 不上报 |
| 置信度 < 0.6 | **跳过** | — | 证据不足 |

## 注意事项

- `../` 有多种编码绕过方式：URL 编码（`%2e%2e%2f`）、Unicode 编码、双编码（`%252e%252e%252f`）等，仅做简单的字符串过滤不足以防护。
- Zip Slip 是一个特殊的路径遍历变体，经常被独立审计工具忽略，需重点关注。
- 对 `rule_id` 使用有意义的命名：`pathtrav-taint`（污点追踪发现）、`pathtrav-no-canon`（无规范化）、`pathtrav-zipslip`（Zip Slip）。
- 每次调用 `report_finding` 时，`confidence` 应反映确定程度：完整污点路径 + 无任何校验 ≥ 0.9，ZIP 条目名未校验 ≥ 0.85。

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
