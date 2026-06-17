# SQL 注入判断知识

## Use When

Use this skill to validate candidate paths whose sink category is SQL execution,
dynamic HQL/JPA query construction, MyBatis mapper interpolation, or a stored
second-order SQL construction path.

## Candidate Fields That Matter

- `entryPoint`: external HTTP/message/scheduled source and route.
- `sink`: SQL API, mapper statement, file path and line.
- `methodPath` / `callEdges`: whether the proposed dispatch path is plausible.
- `taintConfidence` and `sourceClassification`: whether request-controlled or
  stored attacker-controlled data reaches the SQL construction.
- `storedCandidate.writePath`, `readAccess`, and `executionPath` for second-order
  candidates.

## Common Verdict Rules

- Confirm only when source/reachability, propagation, SQL sink/text, and missing
  or bypassed protection are visible.
- Downgrade when production profile, route reachability, trust boundary, mapper
  dispatch, or runtime configuration is ambiguous.
- Mark NEEDS_REVIEW when the SQL action is sensitive but binding, allowlist,
  mapper, or field-correspondence evidence is incomplete.
- Suppress only when effective protection is visible and applies before SQL text
  is executed.

Effective protection must cover the actual SQL fragment, identifier, operator,
sort clause, or bound value that attacker input influences. It must run before
execution and remain effective after later string building, mapper expansion,
dynamic SQL tags, template rendering, or dispatch indirection.

For stored or second-order candidates, confirm field correspondence: the
externally written field, DB column, mapper property, cache key, serialized
property, or config key must be the same value later read and used by the SQL
sink. Repository/entity identity alone is supporting evidence.

## Confirmed Vulnerability Conditions

| Condition | Verdict | Severity |
|---|---|---|
| Request value is concatenated into JDBC `Statement.execute*()` SQL | Confirm | HIGH |
| Request value is concatenated into HQL/JPA `createQuery` or `createNativeQuery` SQL text | Confirm | HIGH |
| MyBatis XML or annotation uses `${...}` with externally influenced value | Confirm | HIGH |
| Stored field written from an external entrypoint is later concatenated into SQL | Confirm | HIGH |
| Blacklist or partial keyword filtering exists but SQL is still string-built | Confirm | MEDIUM |

For MyBatis dynamic identifiers such as `ORDER BY ${column}`, confirm whether
the value is strictly selected from a server-side enum/allowlist. If it is a
free-form request value, treat it as injectable even when only a column or sort
direction is controlled.

`${}` is acceptable only when the value is selected from a closed server-side
allowlist, such as enum-mapped column names or sort directions.

## False Positive Suppressors

Do not report when the sink uses true parameter binding:

- JDBC `PreparedStatement` with `?` placeholders and all attacker values bound
  via setter methods.
- MyBatis `#{...}` placeholders.
- Hibernate/JPA named parameters such as `:name` with `setParameter`.
- Criteria API, QueryDSL, JOOQ bind values, or ORM query builders that bind
  attacker-controlled values as parameters.
- Dynamic table/column names selected only from a closed server-side allowlist.

If `PreparedStatement` is used but the SQL template itself is concatenated with
attacker input before placeholders are bound, the issue remains valid.

Do not suppress Criteria/QueryDSL/JOOQ/ORM builder usage when attacker input
controls raw SQL fragments, identifiers, operators, order clauses, or template
strings.

LIKE wildcard abuse caused by `%` or `_` in a bound parameter is usually a
business logic or excessive-search issue, not SQL injection, unless the SQL text
itself is string-built.

## Severity And Confidence

- HIGH/HIGH: direct request-controlled value reaches string-built SQL.
- HIGH/MEDIUM: second-order stored value reaches string-built SQL and field
  correspondence is plausible but not fully proven.
- MEDIUM/MEDIUM: sanitizer exists but is blacklist-based, partial, or applied
  before later unsafe concatenation.
- Suppress: strict allowlist or parameter binding fully covers the attacker
  controlled value.

## Evidence Requirements

A valid SQL injection finding should cite:

- External entrypoint and parameter or stored field.
- The propagation step that carries the value into SQL text.
- The exact SQL construction line.
- Why parameter binding or a strict allowlist is absent or insufficient.
- Suppressors considered and why they do not apply.

`rule_id` values: `sqli-taint`, `sqli-mybatis-unsafe`, `sqli-second-order`.
