# 不安全解析（反序列化 + XXE）判断知识

本类别覆盖两类解析不可信数据格式的风险：对象反序列化和 XML 外部实体注入。

---

## A. 反序列化漏洞判断规则

**① 原生 Java 反序列化（ObjectInputStream.readObject）**
- HTTP 控制器或 MQ 消费者中 + 无 `ObjectInputFilter` → **CRITICAL**
- 来源不明 / 文件读取 → **MEDIUM**
- 即使当前缺少已知 gadget chain，入口点仍应上报——依赖升级可能引入新 gadget

**② JSON 危险配置**
- Fastjson `setAutoTypeSupport(true)` + 接收外部 JSON → **HIGH**
- Jackson `enableDefaultTyping(OBJECT_AND_NON_CONCRETE)` 或 `activateDefaultTyping` → **HIGH**
- 默认配置（autoType 未开启）→ 安全

**③ XML 反序列化**
- `XMLDecoder.readObject()` → **CRITICAL**
- `XStream.fromXML()` 未调用 `setupDefaultSecurity()` → **HIGH**
- JAXB unmarshal 输入来自 HTTP → **MEDIUM**

**④ YAML 反序列化**
- SnakeYAML `Yaml.load()` 接收外部输入 → **HIGH**（可构造任意对象）
- `Yaml.loadAs(input, SafeType.class)` 仍可能危险

**⑤ Serializable 接口直接暴露**
- Controller 直接接收 Serializable 子类参数 → **MEDIUM**

### 反序列化验证要点

- 沿候选路径检查 NATIVE_DESERIALIZATION / DYNAMIC_LOADING sink
- 检查是否有 `ObjectInputFilter` / `resolveClass` 白名单子类
- 对 JSON/XML 库检查全局配置（可能在配置类中而非调用点）
- 用 Grep 搜索 `enableDefaultTyping`、`autoType`、`XStream` 的安全配置

`rule_id` 命名：`deser-native`、`deser-json`、`deser-xml`、`deser-yaml`、`deser-api`。

---

## B. XXE（XML 外部实体注入）判断知识

XML 解析器未禁用外部实体时，攻击者可读取任意文件、发起 SSRF 或 DoS。

**安全配置（存在任意一项即视为安全）**：
- `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
- `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`
- `factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)`
- `factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)`

### XXE 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 候选路径终点为 XML 解析 + 用户可控输入 + 无安全配置 | **漏洞** | CRITICAL |
| XML 解析工厂未配置安全特性 + 在 REST 控制器/公开端点中 | **漏洞** | HIGH |
| XML 解析工厂未配置安全特性 + 仅在内部处理（无 HTTP 入口）| **漏洞** | MEDIUM |
| 工厂已配置上述任一安全特性 | 安全 | — |

### XXE 验证要点

- 沿候选路径检查 XML_PARSE sink：定位 XML 解析工厂的创建代码
- 在工厂创建到 `parse()` 调用之间搜索安全配置（`setFeature`/`setProperty`）
- 检查工厂是否通过工具类创建（类名含 Secure/Safe/XXEUtil → 可能已配置安全）
- 注意：同一类中工厂的安全配置可能在另一个方法中设置

`rule_id` 命名：`xxe-taint`、`xxe-unsafe-factory`。
