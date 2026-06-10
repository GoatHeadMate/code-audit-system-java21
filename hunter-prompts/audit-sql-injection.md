# SQL 注入判断知识

## 查询结果说明

| 文件 | 含义 |
|------|------|
| `find_sources.json` | 所有 SQL 参数来源（HTTP 入口） |
| `find_sinks.json` | 所有 SQL 执行点 |
| `trace_taint.json` | 端到端污点路径（已内置净化器建模，每条直接等于已确认漏洞） |
| `find_sanitizers.json` | 净化器和参数绑定检查 |
| `mybatis_unsafe.json` | MyBatis `${}` 不安全插值 |
| `second_order.json` | 二阶注入路径（数据库读值→拼接入 SQL） |

## 判断规则

**① 污点路径（trace_taint）：** 每条路径直接确认漏洞，无需再验证。
- JDBC Statement 拼接 / Hibernate HQL 拼接 / JPA createNativeQuery → severity HIGH

**② MyBatis `${}`（mybatis_unsafe）：** 每条结果均为漏洞，severity HIGH。
- 检查是否存在黑名单过滤（同文件或 Service 层），有则降为 MEDIUM

**③ 二阶注入（second_order）：**
- ResultSet.getXxx() → SQL 拼接 → severity HIGH

**④ 去重合并：** 同一文件多个同类漏洞合并为一条，列出所有行号。

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

`rule_id` 命名：`sqli-taint`、`sqli-mybatis-unsafe`、`sqli-second-order`。

**build-mode=none 限制**：Sink 参数为非字面量表达式即可上报，不要因缺少完整 Source→Sink 路径而拒绝上报。
