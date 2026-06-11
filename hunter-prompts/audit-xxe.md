# XXE（XML 外部实体注入）判断知识

XML 解析器未禁用外部实体时，攻击者可读取任意文件、发起 SSRF 或 DoS。

**安全配置（存在任意一项即视为安全）**：
- `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
- `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`
- `factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)`
- `factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)`

## 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| 候选路径终点为 XML 解析 + 用户可控输入 + 无安全配置 | **漏洞** | CRITICAL |
| XML 解析工厂未配置安全特性 + 在 REST 控制器/公开端点中 | **漏洞** | HIGH |
| XML 解析工厂未配置安全特性 + 仅在内部处理（无 HTTP 入口）| **漏洞** | MEDIUM |
| 工厂已配置上述任一安全特性 | 安全 | — |

## 验证要点

- 沿候选路径检查 XML_PARSE sink：定位 XML 解析工厂的创建代码
- 在工厂创建到 `parse()` 调用之间搜索安全配置（`setFeature`/`setProperty`）
- 检查工厂是否通过工具类创建（类名含 Secure/Safe/XXEUtil → 可能已配置安全）
- 注意：同一类中工厂的安全配置可能在另一个方法中设置

`rule_id` 命名：`xxe-taint`、`xxe-unsafe-factory`。
