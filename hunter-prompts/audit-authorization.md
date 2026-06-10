# 越权漏洞判断知识

## 查询结果说明

| 文件 | 含义 |
|------|------|
| `missing_security_config.json` | 缺少全局 SecurityFilterChain 等安全配置 |
| `debug_bypass.json` | 调试参数绕过认证的分支（后门） |
| `unprotected.json` | 缺少权限注解的接口 |
| `resource_ids.json` | 携带资源 ID 参数的接口（潜在 IDOR） |
| `endpoints.json` | 所有 HTTP 接口（全量攻击面） |
| `global_auth.json` | 全局拦截器/过滤器是否存在 |
| `jaxrs_missing_auth.json` | JAX-RS 接口缺少认证注解 |

## 判断规则（按优先级）

**① 全局无防护（最高优先）**
- `missing_security_config` 非空 **且** `global_auth` 为空 → 整个模块无认证保护 → 批量上报 **HIGH**

**② 调试后门（次高优先）**
- `debug_bypass` 非空 → 每条结果独立上报 **CRITICAL**

**③ IDOR 越权**
- `resource_ids` 的接口无资源归属校验（从 session/token 提取用户 ID 并与资源比对） → **HIGH IDOR**

**④ 管理员接口垂直越权**
- 接口路径/方法名含 `admin/manage/system/root` 且无角色注解 → **HIGH**

**⑤ 全局拦截存在，个别接口遗漏**
- `global_auth` 非空但 `unprotected` 仍有接口 → **MEDIUM**

**注意**：全局认证中间件只验证身份，不能防止 IDOR。同一文件/模块的同类漏洞必须合并。

`rule_id` 命名：`authz-unprotected`、`authz-idor`、`authz-vertical`、`authz-missing-config`、`authz-debug-bypass`、`authz-jaxrs-unprotected`。

**build-mode=none 限制**：Sink 为非字面量即可上报，全局无防护情况下无需完整路径证据。
