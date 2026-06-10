# 反序列化漏洞判断知识

## 查询结果说明

| 文件 | 含义 |
|------|------|
| `native_deser.json` | ObjectInputStream.readObject() 调用（已排除 resolveClass 白名单子类） |
| `json_unsafe.json` | JSON 库危险配置（Fastjson autoType / Jackson enableDefaultTyping） |
| `xml_deser.json` | XStream / XMLDecoder / JAXB unmarshal 入口 |
| `serializable_api.json` | Serializable 类直接暴露在 HTTP 接口中 |

## 判断规则

**① native_deser（原生反序列化）**
- HTTP 控制器或 MQ 消费者中 + 无 ObjectInputFilter → **CRITICAL**
- 来源不明 / 文件读取 → **MEDIUM**

**② json_unsafe（JSON 危险配置）**
- Fastjson `setAutoTypeSupport(true)` + 接收外部 JSON → **HIGH**
- Jackson `enableDefaultTyping(OBJECT_AND_NON_CONCRETE)` → **HIGH**
- 默认配置（autoType 未开启）→ 安全

**③ xml_deser（XML 反序列化）**
- `XMLDecoder.readObject()` → **CRITICAL**
- `XStream.fromXML()` 未调用 `setupDefaultSecurity()` → **HIGH**
- JAXB unmarshal 输入来自 HTTP → **MEDIUM**

**④ serializable_api**
- Controller 直接接收 Serializable 子类参数 → **MEDIUM**

即使当前缺少已知 gadget chain，入口点仍应上报——依赖升级可能引入新 gadget。

`rule_id` 命名：`deser-native`、`deser-json`、`deser-xml`、`deser-api`。

**build-mode=none 限制**：Sink 参数为非字面量即可上报。
