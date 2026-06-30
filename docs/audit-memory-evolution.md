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
- Recall similar historical findings into task-level `memory_priors`.
- Inject priors into hunter tasks as context only.
- Keep all current source validation inside the hunter workflow.

This keeps learning observable and reversible while giving agents better
attention without letting historical mistakes become automatic judgments.
