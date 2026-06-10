# XXE（XML 外部实体注入）判断知识

XML 解析器未禁用外部实体时，攻击者可读取任意文件、发起 SSRF 或 DoS。

安全配置（存在任意一项即视为安全）：
- `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
- `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`
- `factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)`
- `factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)`

## 查询结果说明

| 文件 | 含义 |
|------|------|
| `xml_sources.json` | 所有 XML 解析调用点 |
| `xml_unsafe.json` | 工厂创建后当前方法内未见安全配置的位置 |
| `xxe_taint.json` | 用户输入流向 XML 解析器的污点路径 |

## 判断规则

**① xxe_taint 有路径** → 用户可控输入 → XML 解析 → **CRITICAL**

**② xml_unsafe 有结果**
- 在 REST 控制器或公开端点中 → **HIGH**
- 仅在内部处理（无 HTTP 入口）→ **MEDIUM**

**③ 安全排除**
- 工厂已配置上述任一安全特性 → 不上报
- 类名含 Secure/Safe/XXEUtil → 不上报

`rule_id` 命名：`xxe-taint`、`xxe-unsafe-factory`。

**build-mode=none 限制**：xml_unsafe 中存在非字面量参数传入 parse() 即可上报。
