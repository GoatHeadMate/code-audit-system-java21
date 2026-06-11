# SQL 注入判断知识

## 判断规则

| 场景 | 判定 | 严重度 |
|------|------|--------|
| `Statement.execute("SQL" + input)` | **漏洞** | HIGH |
| HQL `createQuery("FROM X WHERE a=" + input)` | **漏洞** | HIGH |
| MyBatis `${}` 字符串插值（XML 或注解） | **漏洞** | HIGH |
| 数据库读值 → 拼接入 SQL（二阶注入） | **漏洞** | HIGH |
| 有黑名单过滤但未参数化 | **漏洞** | MEDIUM |
| `PreparedStatement` + 参数绑定 `?` | 安全 | — |
| MyBatis `#{}` 占位符 | 安全 | — |
| Hibernate 命名参数 `:name` | 安全 | — |

**① 直接拼接（最强证据）**
- 候选路径显示 HTTP 参数值沿调用链传递到 SQL 字符串拼接点 → **HIGH**，confidence ≈ 0.85
- JDBC `Statement` 拼接 / Hibernate HQL 拼接 / JPA `createNativeQuery` 均属此类

**② MyBatis `${}` 不安全插值**
- XML mapper 中使用 `${param}` 而非 `#{param}` → **HIGH**
- 检查是否存在 Service 层黑名单过滤，有则降为 **MEDIUM**
- 常见于 ORDER BY、表名动态传入等场景——即使只有列名可控也可注入

**③ 二阶注入**
- 存储型候选：HTTP 写入 → 数据库存储 → 读取后拼接入 SQL → **HIGH**
- 确认存储字段与读取字段的实体对应关系

**④ 去重合并**
- 同一文件多个同类漏洞合并为一条，列出所有行号

## 验证要点

- 检查 sink 处的 SQL 构造方式：字符串拼接 vs 参数绑定
- 如果是 `PreparedStatement` 但 SQL 字符串本身是动态拼接的，仍然有漏洞
- 用 Grep 搜索 mapper XML 中的 `${` 确认 MyBatis 不安全插值

`rule_id` 命名：`sqli-taint`、`sqli-mybatis-unsafe`、`sqli-second-order`。
