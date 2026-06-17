# 不安全解析（反序列化 + XXE）判断知识

## Use When

Use this skill to validate candidate paths ending in object deserialization,
dynamic type loading, unsafe JSON/XML/YAML parsing, XML entity resolution, or
parser factory misconfiguration.

## Candidate Fields That Matter

- `entryPoint`: HTTP body/file/message/source of serialized data.
- `sink`: parser/deserializer API and line.
- `methodPath` / `callEdges`: whether the parser configuration object reaches
  the sink.
- `taintConfidence` and `sourceClassification`: external bytes/string vs trusted
  internal config.
- Dependencies and parser versions where available.
- Factory/config calls near the sink or in helper methods.

## Common Verdict Rules

- Confirm only when source/reachability, propagation, parser/deserializer sink,
  and missing or bypassed protection are visible.
- Downgrade when production profile, route reachability, trust boundary, parser
  version, or runtime configuration is ambiguous.
- Mark NEEDS_REVIEW when the parser sink is sensitive but type binding, factory
  configuration, version, or trust-boundary evidence is incomplete.
- Suppress only when effective protection is visible and applies before the
  parser/deserializer sink.

Effective protection must configure the actual parser/factory/mapper instance
used by the sink, cover the actual input format and target type, and remain
effective after helper indirection, polymorphic type handling, factory wrapping,
entity resolver replacement, or dispatch indirection.

For stored or second-order candidates, confirm field correspondence: the
externally written field, DB column, mapper property, cache key, serialized
property, or config key must be the same value later read and used by the sink.
Repository/entity identity alone is supporting evidence.

## Deserialization Conditions

| Condition | Verdict | Severity |
|---|---|---|
| External data reaches `ObjectInputStream.readObject()` without `ObjectInputFilter` or class allowlist | Confirm | CRITICAL |
| Native deserialization source is file/cache/message of unclear trust | Confirm | MEDIUM |
| `XMLDecoder.readObject()` receives external data | Confirm | CRITICAL |
| XStream `fromXML()` without `setupDefaultSecurity()`/type allowlist | Confirm | HIGH |
| Fastjson AutoType is enabled for external JSON | Confirm | HIGH |
| Jackson default typing is enabled for external polymorphic input | Confirm | HIGH |
| SnakeYAML `Yaml.load()` receives external data with arbitrary object construction possible | Confirm | HIGH |
| Parser is configured with strict allowed target type and no polymorphic type control | Suppress | — |

Lack of a visible gadget chain does not suppress unsafe native deserialization
when untrusted data reaches object construction. It may reduce confidence if
dependencies are minimal and no dangerous type surface is visible.

Jackson is dangerous when external input can control polymorphic type metadata
through default typing, `@JsonTypeInfo`, or permissive subtype validators.
Binding to a fixed DTO without polymorphic type control should normally suppress.

Fastjson findings should cite AutoType state, parser feature configuration,
version evidence when available, and whether attacker input can control type
metadata such as `@type`.

## XXE Conditions

| Condition | Verdict | Severity |
|---|---|---|
| External XML reaches parser and DTD/external entities are not disabled | Confirm | CRITICAL |
| Parser factory lacks secure features in a public endpoint | Confirm | HIGH |
| Parser factory lacks secure features only for internal trusted config | Downgrade | MEDIUM/LOW |
| DTD and external entities are disabled before parsing | Suppress | — |

Secure XML evidence includes one or more effective controls such as:

- `disallow-doctype-decl=true`
- `XMLConstants.FEATURE_SECURE_PROCESSING=true` when sufficient for the parser
- `XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES=false`
- `XMLInputFactory.SUPPORT_DTD=false`
- `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_SCHEMA` restricted to empty values

For XML parsers, check the specific factory type: `DocumentBuilderFactory`,
`SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`,
JAXB, dom4j, JDOM, and `SAXReader`. Secure features must be applied to the
actual factory instance used by the sink.

## False Positive Suppressors

Do not report when:

- Input is fixed server-side data, not external or stored attacker-controlled
  content.
- Deserialization target is a final/simple DTO without polymorphic type control
  and the library configuration prevents arbitrary type resolution.
- A class allowlist/filter is enforced before object construction.
- XML parser helper is known to configure secure features before every parse.
- A secure helper returns or configures the same parser/factory object actually
  used by the parse call.

## Severity And Confidence

- CRITICAL/HIGH: external bytes/XML reach native deserialization, XMLDecoder, or
  XXE-capable parser without visible protection.
- HIGH/HIGH: dangerous JSON/YAML/XML library setting is enabled for external data.
- MEDIUM/MEDIUM: trust boundary is ambiguous or parser is internal-only.
- Suppress: strong filter/allowlist/secure parser configuration is visible.

## Evidence Requirements

A valid finding should cite:

- The external data source.
- The parser/deserializer construction and sink.
- The missing or insufficient safety configuration.
- For library-specific issues, the dangerous setting or absence of allowlist.
- Suppressors considered and why they do not apply.

`rule_id` values: `deser-native`, `deser-json`, `deser-xml`, `deser-yaml`,
`deser-api`, `xxe-taint`, `xxe-unsafe-factory`.
