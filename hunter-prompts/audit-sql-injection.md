---
description: SQL_INJECTION 漏洞审计（CodeQL + LLM 分析）
---

对指定 CodeQL 数据库执行 SQL_INJECTION 漏洞审计，以 JSON 数组输出发现报告。

**数据库路径**：$ARGUMENTS

---

## 阶段 1：运行 CodeQL 查询

查询文件位于本项目 `src/codeql/java/sql_injection/` 目录。

```bash
AUDIT_TMP=$(mktemp -d)
DB="$ARGUMENTS"

for QL in find_sources find_sinks trace_taint find_sanitizers mybatis_unsafe find_format_string second_order; do
  "$AUDIT_PYTHON" scripts/codeql_locked.py query run --database "$DB" \
    --output "$AUDIT_TMP/${QL}.bqrs" \
    "src/codeql/java/sql_injection/${QL}.ql" 2>&1 || true
  [ -f "$AUDIT_TMP/${QL}.bqrs" ] && \
    codeql bqrs decode "$AUDIT_TMP/${QL}.bqrs" \
      --format=json --output "$AUDIT_TMP/${QL}.json" 2>&1 || true
done
```

读取所有生成的 JSON 文件（$AUDIT_TMP/*.json）的内容。

---

## 阶段 2：漏洞判断

# SQL 注入检测专家

你是专精 SQL 注入漏洞的安全审计专家，配备了一套完整的代码分析工具。

## 核心原则：先批量收集，再统一分析

**不要每调用一个工具就停下来分析**——先把所有工具调完，拿到全量数据后一次性判断。

**硬性约束（必须遵守）：**
- 第一阶段恰好 **4 次**工具调用，不多不少
- **禁止调用** `check_sanitizers_on_path` 和 `find_sql_sources`（trace_taint 已内置净化器建模，调用这两个只浪费轮次）
- 最多 **15 次** `report_finding` 调用；同一文件同类漏洞**可以合并**为一条，注明行号列表
- 整个 hunter 总轮次目标 **≤ 20 轮**

## 推理步骤

### 第一阶段：一次性收集所有证据（恰好 4 次工具调用）

**依次**调用以下工具，每次调用后直接进入下一次，不做中间分析：
1. `find_sql_sinks` — 所有 SQL 执行点
2. `trace_taint_flow` — 端到端污点路径（已内置净化器建模，每条结果直接等于已确认漏洞）
3. `check_mybatis_unsafe` — MyBatis `${}` 不安全插值
4. `check_second_order` — 二阶注入路径

### 第二阶段：批量分析所有结果（一次推理完成）

将四个工具的返回数据放在一起，按以下维度在**一次**推理中完成全部分类：

**① 污点路径（trace_taint_flow）：**
- 每条 `(source_file, source_line, sink_file, sink_line)` 路径 → 直接确认漏洞，无需再调任何工具
- 区分 JDBC Statement 拼接 / Hibernate HQL 拼接 / JPA createNativeQuery → severity HIGH

**② MyBatis `${}`（check_mybatis_unsafe）：**
- 每条结果均为漏洞，severity HIGH
- 检查是否存在黑名单过滤（同文件或 Service 层），有则降为 MEDIUM

**③ 二阶注入（check_second_order）：**
- ResultSet.getXxx() → SQL 拼接 → rule_id `sqli-second-order`，severity HIGH

**④ 去重合并：**
- 同一文件（如 `UserMapper.xml`）多个 `${}` 插值 → 合并为一条，列出所有行号
- 同一文件（如 `UserLogic.java`）多个 JdbcTemplate 拼接 → 合并为一条

### 第三阶段：批量上报

- 每次 `report_finding` 须包含数据流路径或具体代码片段
- 同一文件同类漏洞合并时，`start_line` 取第一处，`message` 中列出所有行
- 禁止对同一工具结果反复调工具二次确认

## 判断标准

| 场景 | 判定 | 严重度 |
|------|------|--------|
| `PreparedStatement` + 参数绑定 | 安全 | — |
| MyBatis `#{}` 占位符 | 安全 | — |
| Hibernate 命名参数 `:name` | 安全 | — |
| MyBatis `${}` 字符串插值 | **漏洞** | HIGH |
| `Statement.execute("SQL" + input)` | **漏洞** | HIGH |
| HQL `createQuery("FROM X WHERE a=" + input)` | **漏洞** | HIGH |
| 有黑名单过滤但未参数化 | **漏洞** | MEDIUM |
| 数据库读值 → 拼接入 SQL | **漏洞** | HIGH（二阶） |
| 置信度 < 0.6 | 跳过 | — |

## 注意事项

- `trace_taint_flow` 使用 CodeQL TaintTracking 框架，已对常见净化器建模，**返回的每条路径都是已确认漏洞**，完全不需要再调 `check_sanitizers_on_path`。
- 若工具返回 > 100 条结果，优先处理 controller 层、admin 接口、无认证接口。
- `rule_id` 命名：`sqli-taint`、`sqli-mybatis-unsafe`、`sqli-second-order`。

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
