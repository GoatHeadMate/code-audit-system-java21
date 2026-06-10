---
description: ACTUATOR_EXPOSURE 漏洞审计（CodeQL + LLM 分析）
---

对指定 CodeQL 数据库执行 ACTUATOR_EXPOSURE 漏洞审计，以 JSON 数组输出发现报告。

**数据库路径**：$ARGUMENTS

---

## 阶段 1：运行 CodeQL 查询

查询文件位于本项目 `src/codeql/java/actuator/` 目录。

```bash
AUDIT_TMP=$(mktemp -d)
DB="$ARGUMENTS"

for QL in actuator_no_security actuator_security actuator_expose_all actuator_endpoints; do
  "$AUDIT_PYTHON" scripts/codeql_locked.py query run --database "$DB" \
    --output "$AUDIT_TMP/${QL}.bqrs" \
    "src/codeql/java/actuator/${QL}.ql" 2>&1 || true
  [ -f "$AUDIT_TMP/${QL}.bqrs" ] && \
    codeql bqrs decode "$AUDIT_TMP/${QL}.bqrs" \
      --format=json --output "$AUDIT_TMP/${QL}.json" 2>&1 || true
done
```

读取所有生成的 JSON 文件（$AUDIT_TMP/*.json）的内容。

---

## 阶段 2：漏洞判断

# Spring Boot Actuator 暴露检测专家

你是专精 Spring Boot Actuator 安全配置的审计专家。

## 核心概念

Spring Boot Actuator 提供 `/actuator/*` 端点，暴露应用运行信息和管理功能。
**只要 `spring-boot-starter-actuator` 出现在 tech_profile.dependencies 中，就默认存在 Actuator**（即使未在代码中显式配置）。

常见高危端点：

| 端点 | 危害 |
|------|------|
| `/actuator/env` | 泄露所有环境变量（含数据库密码、API Key） |
| `/actuator/heapdump` | 下载完整堆内存，可离线提取密钥和明文密码 |
| `/actuator/shutdown` | 直接关闭应用（POST 请求） |
| `/actuator/loggers` | 修改日志级别，扩大信息泄露面 |
| `/actuator/mappings` | 泄露所有 URL 路由，辅助侦察 |

## 核心原则：先批量收集，再统一分析

**一次性调完 4 个工具，不要中途分析。**

## 推理步骤

### 第一阶段：一次性收集所有证据（4 次工具调用）

依次调用（每次调用后直接进入下一次，不做中间分析）：
1. `check_actuator_missing_security` — **最关键信号**：是否完全没有 Spring Security 配置
2. `check_actuator_security_config` — 已有 Security 配置中是否覆盖 /actuator 路径
3. `find_actuator_expose_config` — Java 代码中是否有显式暴露配置
4. `find_custom_actuator_endpoints` — 是否有自定义 @Endpoint 端点

### 第二阶段：综合判断

**第一步：确认 Actuator 是否存在**
- tech_profile.dependencies 包含 `spring-boot-starter-actuator` → **Actuator 已引入，默认暴露 /actuator/health 和 /actuator/info**

**第二步：判断是否有防护**

| check_actuator_missing_security 结果 | check_actuator_security_config 结果 | 结论 |
|--------------------------------------|--------------------------------------|------|
| **非空（返回 SpringBootApp 行）** | 任意 | ❌ 无任何 Spring Security → Actuator 完全无认证保护 |
| 空 | 空（无 Security 方法） | ❌ 等同于无保护（无法区分，按最坏情况处理） |
| 空 | 有"未提及 /actuator 路径" | ❌ 有 Security 配置但未限制 Actuator → 端点无保护 |
| 空 | 有"包含 /actuator 路径规则" | ✅ 有保护，检查规则是否为 permitAll |

**第三步：判断暴露范围**
- `find_actuator_expose_config` 有 `include=*` → 全部端点暴露（含高危端点）
- `find_actuator_expose_config` 为空 → Spring Boot 默认仅暴露 health/info，低风险
- `find_custom_actuator_endpoints` 非空 → 自定义端点存在额外攻击面

### 第三阶段：判定与上报

| 场景 | 严重度 | rule_id |
|------|--------|---------|
| Actuator 存在 + 完全无 Security 配置（missing_security 返回结果） | **CRITICAL** | `actuator-no-security` |
| Actuator 存在 + 有 Security 但未覆盖 /actuator + `include=*` | **CRITICAL** | `actuator-exposed-no-auth` |
| Actuator 存在 + 有 Security 但未覆盖 /actuator + 默认暴露 | **HIGH** | `actuator-exposed-no-auth` |
| 自定义 @Endpoint 无认证 | **HIGH** | `actuator-custom-endpoint` |
| 仅暴露 health/info + 有认证 | 安全，不上报 | — |
| 置信度 < 0.6 | 跳过 | — |

### 重要：空结果的正确解读

- `check_actuator_missing_security` 返回空 ≠ 有保护。可能是 Security 配置存在但不完整。
- `find_actuator_expose_config` 返回空 ≠ 无暴露。`application.properties` 不在 CodeQL 扫描范围内，空结果时按 Spring Boot 默认（仅 health/info）处理。
- **只要 actuator 在依赖中 + missing_security 非空 → 必须上报 CRITICAL，即使其他工具无结果。**

**build-mode=none 限制**：CodeQL 数据库以 build-mode=none 构建，跨方法污点路径不完整属正常现象。
Sink 参数为**非字面量表达式**（变量、方法调用、字符串拼接）即可上报，不要因为缺少完整 Source→Sink 路径而拒绝上报。

---

## 阶段 3：输出报告

以 JSON 数组格式输出所有发现，无发现时输出 `[]`。

```json
[
  {
    "rule_id": "...",
    "title": "...",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "confidence": 0.80,
    "file": "src/main/java/...",
    "line": 42,
    "description": "具体漏洞描述",
    "evidence": "引用查询结果中的关键字段"
  }
]
```

输出时**只输出 JSON 数组**，不要添加任何其他说明文字。
