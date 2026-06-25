# SSRF 判断知识

## Use When

Use this skill to validate candidate paths ending in outbound HTTP or URL-fetch
sinks, including `RestTemplate`, Java `HttpClient`, Apache HTTP clients, URL
stream APIs, webhook callbacks, import-by-URL flows, image/PDF fetchers, and
HTTP proxy/forwarder utilities.

## Proxy And Forwarder Endpoints (Request-Controlled By Default)

A proxy/forwarder/gateway endpoint whose purpose is forwarding a caller-supplied
URL or path — e.g. a `request` / `forward` / `distribute` / `route` method on a
backend/gateway/proxy client — is request-controlled by default. Do NOT classify
its outbound target as "server-configured" or "internal backend call" unless you
have traced that no request field reaches the URL, path, host, port, or query.
Custom forwarder clients (not just `RestTemplate` / `HttpClient` / `openConnection`)
count as outbound SSRF sinks. The forwarder often sits behind an interface →
delegate-impl indirection; follow it to the method that builds and issues the
remote request before concluding the URL is fixed.

When such an endpoint applies a `contains()` / `startsWith()` / substring allowlist
on the full URL string, treat it as bypassable (e.g. appending an allowed token as
a query parameter — `/internal/cmd?x=/allowed/path`) and confirm the bypass reaches
a sensitive internal handler.

## Candidate Fields That Matter

- `entryPoint`: the external route and controllable parameter.
- `sink`: outbound request API and line.
- `methodPath` / `callEdges`: wrapper/proxy utilities between entry and sink.
- `taintConfidence` and `sourceClassification`: full URL control vs partial
  path/query control.
- Nearby validation logic: allowlists, scheme checks, IP/private-range checks,
  DNS resolution, redirect handling, and credential/header injection.

## Common Verdict Rules

- Confirm only when source/reachability, propagation, outbound sink/target class,
  and missing or bypassed protection are visible.
- Downgrade when production profile, route reachability, trust boundary, DNS
  behavior, redirect behavior, or runtime configuration is ambiguous.
- Mark NEEDS_REVIEW when the outbound sink is sensitive but URL parsing, DNS/IP
  validation, redirect, or credential-forwarding evidence is incomplete.
- Suppress only when effective protection is visible and applies before every
  outbound request.

Effective protection must cover the actual scheme, authority, host, port,
resolved IP, redirect target, and credential/header forwarding behavior. It must
run before the request and remain effective after URL parsing differences, DNS
resolution, redirects, proxy routing, later decoding, or dispatch indirection.

For stored or second-order candidates, confirm field correspondence: the
externally written field, DB column, mapper property, cache key, serialized
property, or config key must be the same value later read and used by the
outbound sink. Repository/entity identity alone is supporting evidence.

## Confirmed Vulnerability Conditions

| Condition | Verdict | Severity |
|---|---|---|
| Attacker controls full URL and no effective validation exists | Confirm | CRITICAL |
| URL validation uses `contains()` or weak substring matching | Confirm | HIGH |
| URL validation uses `startsWith()` without URI parsing and canonical host checks | Confirm | HIGH |
| Validation happens before a client follows redirects | Confirm | MEDIUM |
| Attacker controls only path/query on a fixed trusted host | Usually confirm only when it reaches sensitive internal behavior | MEDIUM |
| Proxy/forwarder adds internal credentials or cookies to attacker-chosen target | Confirm and upgrade impact | HIGH/CRITICAL |

Weak allowlist bypass examples include:

- `http://whitelisted.com@evil.com`
- `http://evil.com#whitelisted.com`
- `http://internal:8080/path?next=/whitelisted/path`
- Open redirect from an allowed host to an internal host.

Host validation must handle IPv4 decimal/octal/hex/dword forms, IPv6 literals,
IPv4-mapped IPv6, localhost aliases, trailing dots, mixed case, punycode/IDN,
DNS rebinding, and parser differences between validation and request clients.

Private range checks should include localhost, RFC1918, link-local, loopback,
unique-local IPv6, multicast/reserved ranges, and cloud metadata endpoints such
as `169.254.169.254` or provider-specific metadata hostnames.

If redirects are enabled, every redirect target must be revalidated after DNS
resolution. Validating only the first URL is insufficient.

## False Positive Suppressors

Do not report when all relevant checks are present:

- Scheme is restricted to `http`/`https` as intended.
- Host is parsed with URI/URL APIs and compared against a strict allowlist.
- DNS resolution and final IP are checked against private/link-local/metadata
  ranges when internal access is dangerous.
- Redirects are disabled or every redirect target is revalidated.
- User input only controls a path segment on a fixed safe origin and cannot
  influence scheme, authority, host, port, or redirect destination.

## Severity And Confidence

- CRITICAL/HIGH: full URL control can reach internal services or cloud metadata.
- HIGH/HIGH: weak allowlist bypass is concrete and sink is reachable.
- HIGH/MEDIUM: proxy credentials are injected but exact privileged target is not
  fully proven.
- MEDIUM/MEDIUM: only partial URL control or redirect-dependent exploitation.

## Evidence Requirements

A valid SSRF finding should cite:

- The request parameter or stored field controlling the URL.
- The URL construction and outbound request line.
- The validation logic, or the absence of validation.
- A concrete bypass or reachable internal target class when claiming HIGH+.
- Whether internal credentials, cookies, or headers are automatically attached.
- Suppressors considered and why they do not apply.

`rule_id` values: `ssrf-taint`, `ssrf-no-filter`, `ssrf-weak-contains`,
`ssrf-redirect`, `ssrf-proxy`, `ssrf-metadata`.
