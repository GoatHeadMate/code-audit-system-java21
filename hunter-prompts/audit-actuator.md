# Spring Boot Actuator 暴露判断知识

**只要 `spring-boot-starter-actuator` 在依赖中，Actuator 即默认存在。**

高危端点：`/actuator/env`（泄露密码）、`/actuator/heapdump`（下载堆内存）、`/actuator/shutdown`（关闭应用）。

## 判断规则

| 场景 | 严重度 |
|------|--------|
| Actuator 存在 + 完全无 Security 配置 | **CRITICAL** |
| Actuator 存在 + 有 Security 但未覆盖 `/actuator` + `include=*` | **CRITICAL** |
| Actuator 存在 + 有 Security 但未覆盖 `/actuator` + 默认暴露 | **HIGH** |
| 自定义 `@Endpoint` 无认证 | **HIGH** |
| 仅暴露 health/info + 有认证 | 安全，不上报 |

## 验证要点

- 用 Grep 搜索 `actuator` 相关依赖和配置
- 检查 `application.yml`/`application.properties` 中的 `management.endpoints.web.exposure.include`
- 检查 `SecurityFilterChain` 是否覆盖 `/actuator/**` 路径
- 仅在 `test/` 目录下发现 → 降级为 **MEDIUM**
- Spring Boot 默认仅暴露 `/actuator/health` 和 `/actuator/info`
- **只要 actuator 在依赖中 + 无 Security 配置 → 必须上报 CRITICAL**

`rule_id` 命名：`actuator-no-security`、`actuator-exposed-no-auth`、`actuator-custom-endpoint`。
