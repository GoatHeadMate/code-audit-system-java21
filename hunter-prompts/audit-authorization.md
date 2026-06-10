---
description: 越权漏洞审计（CodeQL + LLM 分析）
---

对指定 CodeQL 数据库执行越权漏洞审计，以 JSON 数组输出发现报告。

**数据库路径**：$ARGUMENTS

---

## 阶段 1：运行所有 CodeQL 查询

查询文件位于本项目 `src/codeql/java/authorization/` 目录。

```bash
AUDIT_TMP=$(mktemp -d)
DB="$ARGUMENTS"

for QL in missing_security_config debug_bypass unprotected resource_ids endpoints global_auth jaxrs_missing_auth; do
  "$AUDIT_PYTHON" scripts/codeql_locked.py query run --database "$DB" \
    --output "$AUDIT_TMP/${QL}.bqrs" \
    "src/codeql/java/authorization/${QL}.ql" 2>&1 || true
  [ -f "$AUDIT_TMP/${QL}.bqrs" ] && \
    codeql bqrs decode "$AUDIT_TMP/${QL}.bqrs" \
      --format=json --output "$AUDIT_TMP/${QL}.json" 2>&1 || true
done
```

读取所有生成的 JSON 文件内容。

---

## 阶段 2：漏洞判断

你是专精越权漏洞的安全审计专家。核心概念：

- **未授权访问**：接口没有任何权限控制，攻击者无需认证即可调用敏感功能
- **IDOR**：接口有认证但未校验资源归属，用户 A 可通过篡改 ID 访问用户 B 的数据
- **垂直越权**：普通用户可访问管理员接口
- **调试后门**：通过特殊参数绕过认证检查

### 查询结果说明

| 文件 | 含义 |
|------|------|
| `missing_security_config.json` | 缺少全局 SecurityFilterChain 等安全配置 |
| `debug_bypass.json` | 调试参数绕过认证的分支（后门） |
| `unprotected.json` | 缺少权限注解的接口 |
| `resource_ids.json` | 携带资源 ID 参数的接口（潜在 IDOR） |
| `endpoints.json` | 所有 HTTP 接口（全量攻击面） |
| `global_auth.json` | 全局拦截器/过滤器是否存在 |
| `jaxrs_missing_auth.json` | JAX-RS 接口缺少认证注解 |

### 判断规则（按优先级）

**① 全局无防护（最高优先）**
- `missing_security_config.json` 非空 **且** `global_auth.json` 为空
  → 整个模块无认证保护 → 对该模块下 `unprotected.json` / `jaxrs_missing_auth.json` 的结果批量上报 **HIGH**

**② 调试后门（次高优先）**
- `debug_bypass.json` 非空 → 每条结果独立上报 **CRITICAL**

**③ IDOR 越权**
- `resource_ids.json` 的接口 → 判断方法体是否有资源归属校验（从 session/token 提取用户 ID 并与资源归属比对）
  - 无归属校验 → **HIGH IDOR**
  - 同一文件多个 IDOR 接口合并为一条，注明行号列表

**④ 管理员接口垂直越权**
- 接口路径/方法名含 `admin/manage/system/root` 且无角色注解 → **HIGH**

**⑤ 全局拦截存在，个别接口遗漏**
- `global_auth.json` 非空（有拦截器）但 `unprotected.json` 仍有接口 → **MEDIUM**

**注意**：
- 全局认证中间件只验证身份，不能防止 IDOR。
- 不要对无资源 ID 的纯功能性接口上报 IDOR。
- 同一文件/模块的同类漏洞必须合并，避免重复上报 20 条相同问题。

**build-mode=none 限制**：Sink 为非字面量即可上报，全局无防护情况下无需完整路径证据。

---

## 阶段 3：输出报告

以 JSON 数组格式输出所有发现，无发现时输出 `[]`。同一文件多个同类漏洞合并上报。

```json
[
  {
    "rule_id": "authz-debug-bypass",
    "title": "越权 - 调试参数绕过认证",
    "severity": "CRITICAL",
    "confidence": 0.90,
    "file": "src/main/java/com/example/AdminController.java",
    "line": 23,
    "description": "接口检查 debug=true 参数，存在时直接跳过 token 验证。",
    "evidence": "debug_bypass.json: method=handleRequest, condition=debug==true→skip auth"
  }
]
```

`rule_id` 参考命名：`authz-unprotected`、`authz-idor`、`authz-vertical`、
`authz-missing-config`、`authz-debug-bypass`、`authz-jaxrs-unprotected`。

输出时**只输出 JSON 数组**，不要添加其他说明文字。
