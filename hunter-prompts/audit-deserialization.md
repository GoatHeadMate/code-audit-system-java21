---
description: 反序列化漏洞审计（CodeQL + LLM 分析）
---

对指定 CodeQL 数据库执行反序列化漏洞审计，以 JSON 数组输出发现报告。

**数据库路径**：$ARGUMENTS

---

## 阶段 1：运行所有 CodeQL 查询

查询文件位于本项目 `src/codeql/java/deserialization/` 目录。

```bash
AUDIT_TMP=$(mktemp -d)
DB="$ARGUMENTS"

for QL in native_deser json_unsafe xml_deser serializable_api; do
  "$AUDIT_PYTHON" scripts/codeql_locked.py query run --database "$DB" \
    --output "$AUDIT_TMP/${QL}.bqrs" \
    "src/codeql/java/deserialization/${QL}.ql" 2>&1 || true
  [ -f "$AUDIT_TMP/${QL}.bqrs" ] && \
    codeql bqrs decode "$AUDIT_TMP/${QL}.bqrs" \
      --format=json --output "$AUDIT_TMP/${QL}.json" 2>&1 || true
done
```

读取所有生成的 JSON 文件内容。

---

## 阶段 2：漏洞判断

你是专精反序列化漏洞的安全审计专家。反序列化漏洞的本质：应用在反序列化不可信数据时
未做类型白名单校验，攻击者可构造恶意序列化对象触发任意代码执行。

### 查询结果说明

| 文件 | 含义 |
|------|------|
| `native_deser.json` | ObjectInputStream.readObject() 调用（已排除 resolveClass 白名单子类） |
| `json_unsafe.json` | JSON 库危险配置（Fastjson autoType / Jackson enableDefaultTyping） |
| `xml_deser.json` | XStream / XMLDecoder / JAXB unmarshal 入口 |
| `serializable_api.json` | Serializable 类直接暴露在 HTTP 接口中 |

### 判断规则

**① native_deser.json（原生反序列化）**
- 方法位于 HTTP 控制器或消息队列消费者中 + 无 ObjectInputFilter → **CRITICAL**
- 有 ObjectInputFilter 或 resolveClass 白名单（已被查询排除，不会出现）→ 安全
- 来源不明 / 文件读取 → **MEDIUM**，confidence ≈ 0.65

**② json_unsafe.json（JSON 危险配置）**
- Fastjson `setAutoTypeSupport(true)` + 接收外部 JSON → **HIGH**
- Jackson `enableDefaultTyping(OBJECT_AND_NON_CONCRETE)` → **HIGH**
- Fastjson 1.2.24（无内置黑名单）→ **HIGH**，CVSS 9.8
- 默认配置（autoType 未开启）→ 安全，不上报

**③ xml_deser.json（XML 反序列化）**
- `XMLDecoder.readObject()` 任何情况 → **CRITICAL**（Java 内置，极易利用）
- `XStream.fromXML()` 未调用 `setupDefaultSecurity()` → **HIGH**
- JAXB unmarshal 输入来自 HTTP → **MEDIUM**，confidence ≈ 0.70

**④ serializable_api.json（API 暴露面）**
- Controller 直接接收 Serializable 子类参数 → **MEDIUM**，confidence ≈ 0.65
- 无直接反序列化调用时仅记录为攻击面，不单独上报

**重要说明**：反序列化危害取决于 classpath 是否有可利用 gadget chain。
即使当前缺少已知 gadget，入口点仍应上报——依赖升级可能引入新 gadget。

**build-mode=none 限制**：Sink 参数为非字面量即可上报，不要因缺少完整路径降低到 confidence < 0.5。

---

## 阶段 3：输出报告

多个同类漏洞（如多个 Fastjson 版本、多个 XStream 入口）可合并为一条，注明行号列表。
以 JSON 数组格式输出所有发现，无发现时输出 `[]`。

```json
[
  {
    "rule_id": "deser-native",
    "title": "反序列化 - ObjectInputStream.readObject() 无类型过滤",
    "severity": "CRITICAL",
    "confidence": 0.88,
    "file": "src/main/java/com/example/TaskProcessor.java",
    "line": 78,
    "description": "readObject() 接收 MQ 消息体中的字节流，无 ObjectInputFilter 白名单过滤。",
    "evidence": "native_deser.json: class=TaskProcessor, method=processMessage, no resolveClass override"
  }
]
```

`rule_id` 参考命名：`deser-native`、`deser-json`、`deser-xml`、`deser-api`。

输出时**只输出 JSON 数组**，不要添加其他说明文字。
