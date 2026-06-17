# HTTP 输出注入（XSS + CRLF 注入 + 开放重定向）判断知识

## Use When

Use this skill to validate candidate paths ending in HTTP response body writes,
template rendering, response header writes, or redirect sinks.

## Candidate Fields That Matter

- `entryPoint`: request parameter/body or stored field source.
- `sink`: response writer, template output, header setter, or redirect API.
- `methodPath` / `callEdges`: controller/view/helper path to output.
- `taintConfidence`, `sourceClassification`, and stored candidates.
- Output context: HTML text, HTML attribute, JavaScript, URL, CSS, HTTP header,
  redirect target, and framework/template auto-escaping.

## Common Verdict Rules

- Confirm only when source/reachability, propagation, output sink/context, and
  missing or bypassed protection are visible.
- Downgrade when production profile, route reachability, trust boundary,
  framework version, or runtime content-type behavior is ambiguous.
- Mark NEEDS_REVIEW when the endpoint/output context is sensitive but escaping,
  validation, content type, or runtime framework evidence is incomplete.
- Suppress only when effective protection is visible and applies before the
  output sink.

Effective protection must cover the actual output context, route, field, and
content type. It must run before rendering/header/redirect emission and remain
effective after later decoding, template rendering, redirect normalization,
header construction, or dispatch indirection.

For stored or second-order candidates, confirm field correspondence: the
externally written field, DB column, mapper property, cache key, serialized
property, or config key must be the same value later read and used by the sink.
Repository/entity identity alone is supporting evidence.

## XSS Conditions

| Condition | Verdict | Severity |
|---|---|---|
| Request value is written directly to HTML response without context escaping | Confirm | HIGH |
| Stored external value is rendered into HTML without escaping | Confirm | HIGH |
| Template uses explicit unescaped syntax for external value | Confirm | HIGH |
| Value enters JavaScript/attribute/URL context with only HTML escaping | Confirm | HIGH |
| Framework auto-escapes in the correct context | Suppress | — |
| Missing CSP alone | Informational only | LOW |

Unescaped syntax examples: JSP `<%= ... %>`, Thymeleaf `th:utext`,
FreeMarker `?no_esc`, raw `response.getWriter().write(...)`, and template APIs
that render attacker-controlled template content.

React/Vue/Angular default text binding is usually escaping evidence. Do not
suppress when using `dangerouslySetInnerHTML`, `v-html`, raw HTML pipes, custom
render functions, or server-side rendered raw HTML.

JSON response is usually not XSS by itself unless it is embedded into HTML/JS,
served with executable content type, or consumed by a callback/script context.

## CRLF / Header Injection Conditions

| Condition | Verdict | Severity |
|---|---|---|
| Request value reaches `setHeader`/`addHeader` without CRLF rejection | Confirm | HIGH |
| Redirect/header sink is on framework version known to allow CRLF | Confirm | MEDIUM/HIGH |
| Header value is selected from strict server-side allowlist | Suppress | — |
| Servlet/container rejects CR/LF before writing headers | Suppress or downgrade | —/LOW |

Filtering must reject both raw and decoded CR/LF forms where decoding occurs
before header write.

## Open Redirect Conditions

| Condition | Verdict | Severity |
|---|---|---|
| Request value reaches `sendRedirect` or `redirect:` without target validation | Confirm | MEDIUM |
| Login/SSO return URL accepts absolute external URL | Confirm | MEDIUM/HIGH |
| Relative-path-only check misses `//evil.com` or encoded variants | Confirm | MEDIUM |
| Strict allowlist of host/scheme or safe relative-path normalization exists | Suppress | — |

Open redirects become higher impact when used after login, OAuth/SAML flows, or
trusted internal redirectors.

Relative-path validation must reject `//host`, `\host`, encoded absolute URLs,
mixed slash/backslash variants, and scheme-relative URLs.

## False Positive Suppressors

Do not report when:

- Escaping is context-appropriate for the actual sink context.
- The value is rendered as data by a framework with default escaping and no
  unescaped override is used.
- Header values reject CR/LF after decoding.
- Redirect targets are parsed and restricted to a strict host allowlist or
  normalized safe relative paths that reject `//`, backslashes, and encoded
  absolute URLs.

## Severity And Confidence

- HIGH/HIGH: confirmed unescaped reflected/stored XSS in executable context.
- HIGH/MEDIUM: header injection with uncertain container-level filtering.
- MEDIUM/HIGH: open redirect to arbitrary external host.
- LOW/MEDIUM: missing browser hardening headers without direct injection.

## Evidence Requirements

A valid finding should cite:

- The external or stored value source.
- The output context and sink line.
- The escaping/validation mechanism considered.
- A concrete bypass for weak redirect/header validation when applicable.
- Suppressors considered and why they do not apply.

`rule_id` values: `xss-reflected`, `xss-stored`, `xss-unescaped`,
`xss-no-csp`, `crlf-header`, `crlf-redirect`, `open-redirect-taint`,
`open-redirect-unvalidated`.
