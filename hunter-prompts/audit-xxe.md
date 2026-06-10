---
description: XXE 漏洞审计（CodeQL + LLM 分析）
---

对指定 CodeQL 数据库执行 XXE（XML 外部实体注入）漏洞审计，以 JSON 数组输出发现报告。

**数据库路径**：$ARGUMENTS

---

## 阶段 1：运行所有 CodeQL 查询

查询文件位于本项目 `src/codeql/java/xxe/` 目录。

```bash
AUDIT_TMP=$(mktemp -d)
DB="$ARGUMENTS"

for QL in xml_sources xml_unsafe xxe_taint; do
  "$AUDIT_PYTHON" scripts/codeql_locked.py query run --database "$DB" \
    --output "$AUDIT_TMP/${QL}.bqrs" \
    "src/codeql/java/xxe/${QL}.ql" 2>&1 || true
  [ -f "$AUDIT_TMP/${QL}.bqrs" ] && \
    codeql bqrs decode "$AUDIT_TMP/${QL}.bqrs" \
      --format=json --output "$AUDIT_TMP/${QL}.json" 2>&1 || true
done
```

读取所有生成的 JSON 文件内容。

---

## 阶段 2：漏洞判断

你是专精 XXE 漏洞的安全审计专家。XXE 的本质是：XML 解析器在处理包含外部实体声明的 XML 时，
若未禁用外部实体解析，攻击者可读取任意本地文件、发起 SSRF 或执行 DoS 攻击。

防御配置（存在任意一项即视为安全）：
- `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
- `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`
- `factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)`
- `factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)`

### 查询结果说明

| 文件 | 含义 |
|------|------|
| `xml_sources.json` | 所有 XML 解析调用点（DocumentBuilder.parse、SAXParser.parse 等） |
| `xml_unsafe.json` | 工厂创建后当前方法内未见安全配置的位置（已排除安全工具类） |
| `xxe_taint.json` | 用户输入流向 XML 解析器的污点路径（直接确认漏洞） |

### 判断规则

**① xxe_taint.json 有路径（最强证据）**
- 用户可控输入 → XML 解析 → **CRITICAL**，confidence ≥ 0.90

**② xml_unsafe.json 有结果（次级证据）**
- 出现在 REST 控制器或公开端点的方法中 → **HIGH**，confidence ≈ 0.80
- 仅在内部处理（无 HTTP 入口）→ **MEDIUM**，confidence ≈ 0.65
- 处理固定/内部 XML 内容 → **LOW**，confidence ≈ 0.50

**③ 安全排除**
- 工厂已配置上述任一安全特性 → 安全，不上报
- 类名含 Secure/Safe/XXEUtil 等 → 安全，不上报（工具类本身提供防护封装）

**build-mode=none 限制**：xml_unsafe.json 中存在非字面量参数传入 parse() 即可上报，
不要因为缺少完整污点路径而降至 confidence < 0.5。

---

## 阶段 3：输出报告

以 JSON 数组格式输出所有发现，无发现时输出 `[]`。

```json
[
  {
    "rule_id": "xxe-taint",
    "title": "XXE - 用户可控 XML 输入未禁用外部实体",
    "severity": "CRITICAL",
    "confidence": 0.90,
    "file": "src/main/java/com/example/XmlController.java",
    "line": 55,
    "description": "用户上传的 XML 内容直接传入 DocumentBuilder.parse()，工厂未配置 disallow-doctype-decl。",
    "evidence": "xxe_taint.json: source=@RequestBody xmlContent, sink=DocumentBuilder.parse()"
  }
]
```

`rule_id` 参考命名：`xxe-taint`（用户输入可控）、`xxe-unsafe-factory`（工厂无防护）。

输出时**只输出 JSON 数组**，不要添加其他说明文字。
