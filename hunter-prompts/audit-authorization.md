# 越权漏洞判断知识

## 判断规则（按优先级）

**① 全局无防护（最高优先）**
- 无 Spring Security `SecurityFilterChain` **且** 无全局拦截器/过滤器 → 整个模块无认证保护 → 批量上报 **HIGH**
- 用 Grep 搜索 `SecurityFilterChain`、`WebSecurityConfigurerAdapter`、`HandlerInterceptor`

**② 调试后门（次高优先）**
- 调试参数绕过认证的分支（如 `if (debug)` / `if (request.getParameter("test"))`) → **CRITICAL**

**③ IDOR 越权**
- 接口接收资源 ID 参数但无资源归属校验（未从 session/token 提取用户 ID 与资源比对） → **HIGH**
- 全局认证中间件只验证身份，不能防止 IDOR

**④ 管理员接口垂直越权**
- 接口路径/方法名含 `admin/manage/system/root` 且无角色注解 → **HIGH**
- 用 Grep 搜索 `@PreAuthorize`、`@Secured`、`@RolesAllowed`

**⑤ 全局拦截存在，个别接口遗漏**
- 全局认证非空但个别接口缺少权限检查 → **MEDIUM**

**同一文件/模块的同类漏洞必须合并。**

## 验证要点

- 本类别候选路径覆盖多种高危 sink（命令执行、反序列化、JNDI 等），重点检查路径上是否有认证/授权拦截
- 用 Grep 搜索 `permitAll`、`anonymous`、`antMatchers` 确认安全配置覆盖范围
- JAX-RS 接口检查 `@RolesAllowed` 等注解

`rule_id` 命名：`authz-unprotected`、`authz-idor`、`authz-vertical`、`authz-missing-config`、`authz-debug-bypass`、`authz-jaxrs-unprotected`。
