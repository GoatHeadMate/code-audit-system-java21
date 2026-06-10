/**
 * 查找未禁用外部实体解析的 XML 解析器创建点。
 *
 * 修正（2026-06）：原版只枚举所有 newInstance() 调用，导致：
 *   - DocumentBuilderFactories / SaxParserFactories 等安全包装类被误报
 *   - 同方法内调用了 setFeature(..., false) 的安全配置被误报
 * 现在通过两个排除谓词减少误报：
 *   isSecuredByGuard  — 同方法存在 setFeature/setProperty XXE 防护调用
 *   isInSecureContext — 封装类名含 Secure/Safe/XXE/Util 等安全语义
 */
import java

/** XXE 相关安全 feature/property 名称模式 */
private predicate isXxeSecurityProp(StringLiteral lit) {
  lit.getValue().regexpMatch(
    ".*((disallow-doctype-decl|external-general-entities|external-parameter-entities"
    + "|FEATURE_SECURE_PROCESSING|IS_SUPPORTING_EXTERNAL_ENTITIES|SUPPORT_DTD"
    + "|http://xml\\.org/sax/features|http://apache\\.org/xml/features"
    + "|XMLConstants\\.ACCESS_EXTERNAL)).*"
  )
}

/**
 * 同一方法内调用了 setFeature/setProperty 且参数含 XXE 安全语义。
 * 覆盖：DocumentBuilderFactory, SAXParserFactory, XMLInputFactory 的配置模式。
 */
private predicate isSecuredByGuard(MethodCall creationCall) {
  exists(MethodCall guard |
    guard.getEnclosingCallable() = creationCall.getEnclosingCallable()
    and guard.getMethod().getName() in ["setFeature", "setProperty", "setAttribute"]
    and isXxeSecurityProp(guard.getArgument(0))
  )
}

/**
 * 封装类本身就是安全工具类（通过类名启发式），
 * 如 XXEUtil, DocumentBuilderFactories（注意复数，一般是安全包装）
 */
private predicate isInSecureContext(MethodCall ma) {
  ma.getEnclosingCallable().getDeclaringType().getName().regexpMatch(
    "(?i).*(XXEUtil|SecureXml|XmlSafe|SafeParser|SecureParser"
    + "|SecureDocument|XmlUtils|XmlHelper|SecureHelper).*"
  )
  or
  // 复数形式的 Factory 类（DocumentBuilderFactories / SaxParserFactories）一般是安全包装
  ma.getEnclosingCallable().getDeclaringType().getName()
    .regexpMatch("(?i).*(DocumentBuilder|SaxParser|XmlInput)Factories.*")
  or
  // 方法名本身含 secure 语义
  ma.getMethod().getName().regexpMatch("(?i).*secure.*")
}

from MethodCall ma
where
  ma.getMethod().hasName("newInstance")
  and (
    ma.getMethod().getDeclaringType()
        .hasQualifiedName("javax.xml.parsers", "DocumentBuilderFactory")
    or ma.getMethod().getDeclaringType()
        .hasQualifiedName("javax.xml.parsers", "SAXParserFactory")
    or ma.getMethod().getDeclaringType()
        .hasQualifiedName("javax.xml.stream", "XMLInputFactory")
  )
  and not isSecuredByGuard(ma)
  and not isInSecureContext(ma)
select
  ma.getLocation().getFile().getRelativePath()                     as file,
  ma.getLocation().getStartLine()                                  as line,
  ma.getMethod().getDeclaringType().getName()                      as factory_type,
  ma.getEnclosingCallable().getDeclaringType().getName()           as class_name,
  "XML 解析器工厂创建点，当前方法未见 setFeature/setProperty XXE 防护" as note
