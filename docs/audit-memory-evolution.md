# Audit Memory Evolution

The audit system may learn from historical runs, but memory is an audit prior,
not an audit verdict.

## Principles

- Historical findings, false positives, and PoC results are recalled only as
  attention guidance for the current run.
- Every recalled prior must be re-validated against the current source code
  before it can become a finding.
- Memory must never directly confirm, suppress, or downgrade a finding.
- Automatically generated rules are candidates. Formal rules require a human
  gate, provenance, tests, and rollback capability.
- Rules should carry support statistics, contradiction counts, last-seen time,
  and decay status before they become hard constraints.
- Feedback signals have different trust levels: successful PoC validation is
  stronger than expert confirmation, which is stronger than casual labels.

## Current Minimum Loop

The first implementation is deliberately conservative:

- Append final findings to `audit-memory/findings.jsonl`.
- Append reviewer feedback to `audit-memory/feedback.jsonl`.
- Store feedback as structured learning events with `learning_signal`,
  `poc_status`, `target_severity`, and `learning_note` when available.
- Recall similar historical findings into task-level `memory_priors`.
- Recall false-positive, confirmed, PoC success, PoC failure, risk downgrade,
  duplicate, missed-finding, and approved-rule feedback as task-level priors
  only.
- Generate `audit-memory/rule-candidates.jsonl` from repeated findings and
  feedback.
- Record human rule decisions in `audit-memory/rule-decisions.jsonl`.
- Rewrite approved rule snapshots into `audit-memory/approved-rules.jsonl`.
- Inject priors into hunter tasks as context only.
- Keep rule candidates inactive until human approval promotes them to approved
  priors. Approved priors still require current-source validation.
- Keep all current source validation inside the hunter workflow.

## Implemented Feedback Signals

- `CONFIRM`: confirmed true-positive prior.
- `FALSE_POSITIVE`: false-positive prior; verify the same mitigation or
  reachability break before suppressing.
- `NEEDS_REVIEW`: weak review prior.
- `DUPLICATE`: duplicate-signal prior for rule statistics and reviewer context.
- `RISK_DOWNGRADE`: risk-adjustment prior; verify current impact before lowering
  severity.
- `MISSED_FINDING`: false-negative signal for future attention.
- `POC_SUCCESS`: high-trust true-positive prior.
- `POC_FAILURE`: negative-validation prior; verify the same PoC failure,
  mitigation, or reachability break before suppressing.

This keeps learning observable and reversible while giving agents better
attention without letting historical mistakes become automatic judgments.
