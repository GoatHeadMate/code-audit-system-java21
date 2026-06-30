# 组件漏洞（Actuator + H2 RCE + Log4Shell）判断知识

## Use When

Use this skill to validate component/configuration risks where dependency,
version, profile, exposure, and routing context matter more than a single taint
sink. Covered areas include Spring Boot Actuator exposure, H2 console/INIT RCE,
and Log4Shell-style logging sinks.

## Candidate Fields That Matter

- `techProfile.dependencies`: group/artifact/version when available.
- Config files: application YAML/properties, profile-specific config, env-backed
  values, and management/server port settings.
- Security configuration and route matchers.
- Candidate sink path when user input reaches logging, JNDI lookup, actuator
  endpoint, or H2 configuration.
- Whether evidence is under production source/config or only test fixtures.

## Common Verdict Rules

- Confirm only when dependency/config evidence, production reachability,
  exposure, sensitive endpoint/sink, and missing or bypassed protection are
  visible.
- Downgrade when production profile, route reachability, version, trust boundary,
  or runtime configuration is ambiguous.
- Mark NEEDS_REVIEW when the endpoint/sink is sensitive but authorization,
  version, profile, or runtime configuration evidence is incomplete.
- Suppress only when effective protection or fixed-version evidence is visible
  and applies before exposure or exploitation.

Effective protection must cover the actual management route, component endpoint,
profile, port, base path, logger/JNDI path, or H2 console route. It must not be
bypassed by profile activation, management-port separation, security matcher
order, proxy routing, or alternate endpoint names.

For stored or second-order candidates, confirm field correspondence: the
externally written field, DB column, mapper property, cache key, serialized
property, or config key must be the same value later read and used by the
component sink. Repository/entity identity alone is supporting evidence.

## Actuator Conditions

| Condition | Verdict | Severity |
|---|---|---|
| Actuator dependency exists, sensitive endpoints are exposed, and no auth covers `/actuator/**` | Confirm | CRITICAL |
| `management.endpoints.web.exposure.include=*` and security does not cover actuator | Confirm | CRITICAL |
| Sensitive custom `@Endpoint`/`@RestControllerEndpoint` mutates state without auth | Confirm | HIGH |
| Only `health`/`info` are exposed and security posture is normal | Suppress | — |
| Evidence exists only in test profile or test source | Downgrade | MEDIUM/LOW |

Actuator dependency alone is not enough for CRITICAL. Confirm exposed endpoint
set, security coverage, management port/base path, and production relevance.

Sensitive actuator endpoints include `env`, `configprops`, `heapdump`,
`threaddump`, `logfile`, `loggers`, `shutdown`, `jolokia`, `prometheus` with
sensitive labels, custom state-changing endpoints, and endpoints exposing
secrets or runtime internals.

## H2 Conditions

| Condition | Verdict | Severity |
|---|---|---|
| H2 console is enabled in production and unauthenticated | Confirm | CRITICAL/HIGH |
| H2 console is enabled with weak or missing route security and vulnerable H2 version | Confirm | HIGH/CRITICAL |
| JDBC URL contains `INIT=RUNSCRIPT` or equivalent script loading | Confirm | CRITICAL |
| H2 appears only in tests/dev profile with no production activation | Downgrade or suppress | LOW/MEDIUM |

For H2 console, impact depends on production exposure, authentication, frame
options/security config, and H2 version.

H2 console exposure requires production activation, reachable route, weak or
missing auth, and relevant version/config evidence. Devtools or test-only H2
should be downgraded unless production profile activation is visible.

## Log4Shell Conditions

| Condition | Verdict | Severity |
|---|---|---|
| User-controlled value reaches logger and `log4j-core` 2.0-beta9 through 2.14.1 is present | Confirm | CRITICAL |
| User-controlled value reaches logger and version is unknown or 2.15/2.16 | Confirm | HIGH |
| Direct JNDI lookup sink receives attacker value | Confirm | CRITICAL |
| Version is 2.17.1+ or `log4j-core` is absent | Suppress/downgrade | —/LOW |
| Logging call contains only static text or server-generated IDs | Suppress | — |

Consider mitigations such as `log4j2.formatMsgNoLookups=true`,
`LOG4J_FORMAT_MSG_NO_LOOKUPS`, JndiLookup removal, and fixed versions. Mitigation
quality affects confidence and severity.

`log4j-api` alone is insufficient. Confirm vulnerable Log4Shell only when
`log4j-core` is present and the affected version/configuration is reachable.

## False Positive Suppressors

Do not report when:

- Dependency/config evidence is test-only or inactive for production and no path
  activates it.
- A security filter chain clearly protects the component path and denies
  unauthenticated/unauthorized access.
- Version evidence proves the vulnerable component is fixed and no dangerous
  configuration remains.
- The candidate sink is present but no user-controlled data reaches it.

## Severity And Confidence

- CRITICAL/HIGH: production-exposed RCE-capable component with no effective auth
  or vulnerable Log4Shell taint path.
- HIGH/HIGH: sensitive component exposed with partial auth/version uncertainty.
- MEDIUM/MEDIUM: dev/test/profile ambiguity or mitigated vulnerable component.
- LOW/MEDIUM: informational exposure or fixed version with residual hardening gap.

## Evidence Requirements

A valid component finding should cite:

- Dependency and version evidence, or the absence/ambiguity of version evidence.
- Production config or route exposure evidence.
- Security coverage considered and why it is insufficient.
- Taint path to logger/JNDI when claiming Log4Shell.
- Profile/test-only status when downgrading.
- Suppressors considered and why they do not apply.

`rule_id` values: `actuator-no-security`, `actuator-exposed-no-auth`,
`actuator-custom-endpoint`, `h2-console-exposed`, `h2-init-script`,
`log4shell-taint`, `log4j-version-vulnerable`.

## Output Contract

Use EXACTLY one of these `vuln_type` values (uppercase, underscores, no spaces,
no invented names): `COMPONENT_VULN`, `ACTUATOR_EXPOSURE`, `LOG4SHELL`.
Cross-API combinations use `ATTACK_CHAIN`.

`rule_id` -> `vuln_type`:

- `actuator-no-security` / `actuator-exposed-no-auth` /
  `actuator-custom-endpoint` -> `ACTUATOR_EXPOSURE`
- `h2-console-exposed` / `h2-init-script` -> `COMPONENT_VULN`
- `log4shell-taint` / `log4j-version-vulnerable` -> `LOG4SHELL`

Reporting granularity — one finding per component/configuration root cause (one
Actuator exposure, one vulnerable Log4j path, one H2 console). List affected
endpoints/config keys in evidence rather than emitting one finding per route.

Output anti-patterns:

- BAD: free-form `vuln_type` or invented names.
- BAD: self-numbered `rule_id`; use the vocabulary above.
