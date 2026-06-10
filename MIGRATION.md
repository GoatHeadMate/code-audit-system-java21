# Migration Status

This project is independent from `D:\huawei\code-audit-system`.

## Implemented

- Java 21 and Spring Boot 3.5 runtime
- Existing REST paths and snake_case response contract
- ZIP and Git source ingestion
- Content/commit based CodeQL database cache
- Cache completion marker to reject partial databases
- Java `ProcessBuilder` integration for Git, CodeQL and Claude Code
- Per-database cross-process `FileChannel` query lock
- Maximum 15 concurrent hunters on virtual threads
- Batch CodeQL evidence collection before one Claude call per hunter
- Evidence size limits and partial query error isolation
- Technology profile, Hunter scheduling and finding normalization
- Finding deduplication and attack-chain correlation
- LangChain4j-backed intelligent Orchestrator decisions
- LangGraph4j state graph with evidence preparation, one Supervisor session and
  deterministic finalization
- Native Claude Code custom Subagents generated per audit job
- Exactly one Claude Code operating-system process per audit job
- SSE log streaming
- Existing static frontend, 15 Hunter prompts and 69 CodeQL resources

## Deliberate differences

- Claude is invoked through the local Claude Code executable because there is
  no official Java Agent SDK equivalent to the Python SDK used by the original.
- The Supervisor can use only Agent/Read/Glob/Grep. Native Hunter Subagents can
  use only Read/Glob/Grep. Java retains control of CodeQL and locks.
- CodeQL is collected by Java before Claude analysis. Claude cannot delete or
  contend for CodeQL database locks.

## Remaining production work

- Persist jobs and logs in a database; the current store is in memory.
- Add restart recovery for running jobs.
- Add authentication, authorization and upload quotas.
- Add end-to-end audit fixtures that exercise real CodeQL and Claude credentials.
