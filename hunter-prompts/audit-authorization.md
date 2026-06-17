# 越权漏洞判断知识

## Use When

Use this skill to validate authentication, authorization, IDOR, tenant isolation,
admin-only operation exposure, and debug bypass issues. Authorization review may
use `authorization_surface` entries even when no sink candidate path exists.

## Candidate Fields That Matter

- `authorization_surface`: every selectable HTTP endpoint and its annotations.
- `entryPoint`: route, HTTP method, controller method, and security annotations.
- `methodPath`: service/repository methods that reveal resource owner, tenant,
  role, organization, project, account, or namespace checks.
- `techProfile.security_libs`: Spring Security, Shiro, JAX-RS roles, gateway or
  custom security frameworks.
- Global security configuration: filter chains, interceptors, AOP guards, route
  matchers, `permitAll`, anonymous rules, and gateway assumptions.

## Common Verdict Rules

- Confirm only when source/reachability, propagation, sensitive action, and
  missing or bypassed protection are visible.
- Downgrade when production profile, route reachability, version, trust boundary,
  or runtime configuration is ambiguous.
- Mark NEEDS_REVIEW when the endpoint/action is sensitive but authorization,
  validation, or runtime configuration evidence is incomplete.
- Suppress only when effective protection is visible and applies before the
  sensitive action.

Effective protection must cover the actual route, HTTP method, resource field,
tenant boundary, and dispatch path. It must run before the sensitive action and
must not be bypassed by filter-chain order, `permitAll`, anonymous matchers,
gateway exclusions, route aliases, or later service dispatch.

For stored or second-order candidates, confirm field correspondence: the
externally written field, DB column, mapper property, cache key, serialized
property, or config key must be the same value later read and used by the
sensitive action. Repository/entity identity alone is supporting evidence.

## Confirmed Vulnerability Conditions

| Condition | Verdict | Severity |
|---|---|---|
| Debug/test parameter bypasses authentication or role checks | Confirm | CRITICAL |
| Admin/system/root operation has no role check and no global policy covers it | Confirm | HIGH |
| Resource ID comes from request and no ownership/tenant comparison exists | Confirm | HIGH |
| Global authentication exists but endpoint lacks operation-level authorization for sensitive action | Confirm | MEDIUM/HIGH |
| Whole exposed module has no authentication framework, filter, interceptor, or gateway evidence | Confirm | HIGH |
| JAX-RS/RPC endpoint lacks `@RolesAllowed` or equivalent and no global policy covers it | Confirm | MEDIUM/HIGH |
| Authenticated-only endpoint performs admin/system/security/payment/export/delete/update action without operation-level permission | Confirm | MEDIUM/HIGH |
| Tenant, organization, project, account, or namespace ID can be switched by request without principal-scoped comparison | Confirm | HIGH |

IDOR evidence is strongest when the code loads a resource by request ID and then
updates, deletes, exports, or returns it without comparing owner/tenant/user ID
from the authenticated principal.

Authentication is not authorization: `authenticated()`, login-required, or a
non-null principal only proves identity. Admin/system/security/payment/export/
delete/update operations still require role, permission, tenant, organization,
or ownership checks.

Global security policy must match the exact route, HTTP method, filter-chain
order, and exclusion rules. `permitAll`, anonymous matchers, static exclusions,
or earlier filter chains may bypass later authorization rules.

## False Positive Suppressors

Do not report when any of these are clearly effective:

- A global `SecurityFilterChain`, Shiro filter, gateway, or interceptor covers
  the route and enforces the required role or tenant boundary.
- A service method checks ownership/tenant/organization against the authenticated
  principal before the sensitive operation.
- Repository-scoped access such as `findByIdAndUserId(id, currentUserId)` or
  `findByTenantIdAndId(currentTenantId, id)` constrains the lookup before the
  sensitive operation.
- The resource ID is derived only from the authenticated principal, not from a
  request-controlled parameter.
- The endpoint is health/static/public metadata by design and exposes no
  sensitive operation or object.
- Security annotations are meta-annotations or custom AOP guards; treat them as
  valid when their enforcement point is visible.

## Severity And Confidence

- CRITICAL/HIGH: explicit bypass branch or unauthenticated access to code
  execution/security configuration/admin mutation.
- HIGH/HIGH: sensitive resource/action lacks owner, tenant, or role check.
- MEDIUM/MEDIUM: likely missing operation-level check but global authentication
  exists and impact is not administrative.
- LOW/MEDIUM: informational exposure with weak or ambiguous access policy.

## Evidence Requirements

A valid authorization finding should cite:

- The route and operation.
- The sensitive action or object being accessed.
- The security mechanism expected for the framework.
- The missing or bypassed role/ownership/tenant check.
- Any global policy considered and why it does not cover this route/action.
- Suppressors considered and why they do not apply.

`rule_id` values: `authz-unprotected`, `authz-idor`, `authz-vertical`,
`authz-missing-config`, `authz-debug-bypass`, `authz-jaxrs-unprotected`,
`authz-tenant-bypass`, `authz-authenticated-only`.
