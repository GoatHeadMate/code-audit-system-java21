# 反序列化漏洞判断知识

## 判断规则

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

## 验证要点

- 沿候选路径检查 NATIVE_DESERIALIZATION / DYNAMIC_LOADING sink
- 检查是否有 `ObjectInputFilter` / `resolveClass` 白名单子类
- 对 JSON/XML 库检查全局配置（可能在配置类中而非调用点）
- 用 Grep 搜索 `enableDefaultTyping`、`autoType`、`XStream` 的安全配置

`rule_id` 命名：`deser-native`、`deser-json`、`deser-xml`、`deser-yaml`、`deser-api`。
