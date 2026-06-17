# 代码执行（命令注入 + 模板注入）判断知识

## Use When

Use this skill to validate candidate paths ending in OS command execution,
script execution, dynamic expression evaluation, template evaluation, or stored
second-order execution paths.

## Candidate Fields That Matter

- `entryPoint`: external source, protocol, parameter names, and route.
- `sink`: command/expression/template API and exact line.
- `methodPath` / `callEdges`: constructor, callback, interface dispatch, async,
  scheduled, message, and wrapper method reachability.
- `taintConfidence`, `taintTrace`, and `sourceClassification`: whether attacker
  data reaches the executable part of the sink.
- `storedCandidate`: write path, storage key, read access, execution path, and
  field correspondence for delayed execution.

## Common Verdict Rules

- Confirm only when source/reachability, propagation, sink/action, and missing
  or bypassed protection are visible.
- Downgrade when production profile, route reachability, version, trust boundary,
  or runtime configuration is ambiguous.
- Mark NEEDS_REVIEW when the sink/action is sensitive but authorization,
  validation, or runtime configuration evidence is incomplete.
- Suppress only when effective protection is visible and applies before the sink.

Effective protection must run before command/expression/template execution,
cover the actual value that reaches the sink, use parsed/canonicalized values
where relevant, and remain effective after later decoding, template expansion,
shell wrapping, option parsing, or dispatch indirection.

For stored or second-order candidates, confirm field correspondence: the
externally written field, DB column, mapper property, cache key, serialized
property, or config key must be the same value later read and used by the sink.
Repository/entity identity alone is supporting evidence.

## Command Execution Conditions

| Condition | Verdict | Severity |
|---|---|---|
| Request-controlled value reaches shell command text such as `sh -c`, `bash -c`, `cmd.exe /c`, or `powershell -Command` | Confirm | CRITICAL |
| Request-controlled value reaches `Runtime.exec(String)` or `ProcessBuilder` without shell mode | Confirm when it controls executable path, script path, security-sensitive option, or argument with command-specific semantics | HIGH/CRITICAL |
| Request controls the executable path or first argument of `ProcessBuilder`/`exec(String[])` | Confirm | HIGH |
| Request controls later arguments only | Confirm when argument changes command semantics | MEDIUM/HIGH |
| User input can start with `-` or `--` and alter security-sensitive command behavior | Confirm option injection | MEDIUM/HIGH |
| Template replacement result is executed by shell or command wrapper | Confirm | HIGH/CRITICAL |
| Stored external value is read by scheduled/message/event flow and reaches command text | Confirm | CRITICAL |

Template replacement is dangerous when attacker input controls executable syntax,
flags, shell metacharacters, command substitution, file names interpreted by a
shell, or query strings later embedded into a shell command.

Java `Runtime.exec(String)` is not automatically shell execution. Treat it as
HIGH/CRITICAL only when the attacker can choose the executable/script or can
control command-specific arguments that trigger execution, file overwrite,
configuration loading, plugin loading, proxying, upload/download targets, or
other security-sensitive behavior.

Option injection is valid when user input can begin with `-` or `--` and change
security-sensitive command behavior such as output path, config file, plugin,
script, upload target, proxy, or execution mode.

## Expression And Template Execution Conditions

| Condition | Verdict | Severity |
|---|---|---|
| User or stored value reaches SpEL `parseExpression(...).getValue()` | Confirm | CRITICAL |
| User or stored value reaches MVEL/Groovy/OGNL expression execution | Confirm | CRITICAL |
| User value is treated as FreeMarker/Velocity template source | Confirm | HIGH/CRITICAL |
| User value is only a data variable rendered by a fixed template | Suppress | — |
| Template name is fixed and model data is escaped/non-executable | Suppress | — |

For stored expression candidates, repository identity alone is supporting
evidence. Confirm the same entity field, mapper property, DB column, cache key,
or serialized property is written and later executed.

## False Positive Suppressors

Do not report when:

- The command executable and every security-sensitive argument are selected from
  a closed server-side allowlist.
- User input is passed as a literal data argument to an executable that does not
  interpret it as command syntax, path traversal, option injection, or script.
- Shell mode is not used and attacker input cannot become executable path,
  option, script, or command delimiter.
- Expression/template APIs receive only fixed server-side expressions/templates
  and attacker input is bound as data.

Blacklist character filters, quote escaping, or partial regex checks usually
reduce confidence; they do not suppress unless they form a strict allowlist with
canonicalization.

## Severity And Confidence

- CRITICAL/HIGH: confirmed external or stored taint reaches shell command text
  or expression code.
- HIGH/HIGH: executable path/first argument is controlled without shell mode.
- MEDIUM/MEDIUM: later argument injection or opaque wrapper where exploitability
  depends on command semantics.
- Suppress: strict allowlist or data-only binding is proven.

## Evidence Requirements

A valid finding should cite:

- Entry parameter or stored field.
- The propagation step into command/expression/template text.
- The sink API and line.
- Why sanitization/allowlisting does not prevent executable syntax control.
- For stored flows, the write field and read/execute field correspondence.
- Suppressors considered and why they do not apply.

`rule_id` values: `cmdinj-exec-string`, `cmdinj-exec-args`,
`cmdinj-procbuilder`, `cmdinj-bash-concat`, `cmdinj-template-replace`,
`cmdinj-config-template`, `ssti-spel`, `ssti-mvel`, `ssti-freemarker`,
`ssti-velocity`, `ssti-ognl`, `cmdinj-option-injection`.
