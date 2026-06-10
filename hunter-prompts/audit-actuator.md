# Spring Boot Actuator 暴露判断知识

**只要 `spring-boot-starter-actuator` 在依赖中，Actuator 即默认存在。**

高危端点：`/actuator/env`（泄露密码）、`/actuator/heapdump`（下载堆内存）、`/actuator/shutdown`（关闭应用）。

## 查询结果说明

| 文件 | 含义 |
|------|------|
| `actuator_no_security.json` | 完全没有 Spring Security 配置 |
| `actuator_security.json` | 已有 Security 配置中是否覆盖 /actuator 路径 |
| `actuator_expose_all.json` | Java 代码中是否有显式暴露配置 |
| `actuator_endpoints.json` | 自定义 @Endpoint 端点 |

## 判断规则

| 场景 | 严重度 |
|------|--------|
| Actuator 存在 + 完全无 Security 配置 | **CRITICAL** |
| Actuator 存在 + 有 Security 但未覆盖 /actuator + `include=*` | **CRITICAL** |
| Actuator 存在 + 有 Security 但未覆盖 /actuator + 默认暴露 | **HIGH** |
| 自定义 @Endpoint 无认证 | **HIGH** |
| 仅暴露 health/info + 有认证 | 安全，不上报 |

**空结果解读**：`actuator_no_security` 返回空 ≠ 有保护。`actuator_expose_all` 返回空时按 Spring Boot 默认（仅 health/info）处理。
**只要 actuator 在依赖中 + `actuator_no_security` 非空 → 必须上报 CRITICAL。**

`rule_id` 命名：`actuator-no-security`、`actuator-exposed-no-auth`、`actuator-custom-endpoint`。

**build-mode=none 限制**：Sink 参数为非字面量表达式即可上报。
