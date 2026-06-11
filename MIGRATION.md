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
- Pluggable entrypoint discovery with Spring MVC, JAX-RS and Huawei ROA support
- JDK compiler AST method, invocation, interface implementation and sink index
- Bounded entrypoint-to-sink candidate-path generation before Claude analysis
- Coverage reporting for entrypoint binding, parser diagnostics and unresolved calls
- Evidence size limits and partial query error isolation
- Technology profile, Hunter scheduling and finding normalization
- Finding deduplication and attack-chain correlation
- LangChain4j-backed intelligent Orchestrator decisions
- LangGraph4j state graph with evidence preparation, one Supervisor session and
  deterministic finalization
- Native Claude Code custom Subagents generated per audit job
- Exactly one Claude Code operating-system process per audit job
- SSE log streaming
- Existing static frontend, 15 Hunter prompts and retained legacy CodeQL resources

## Deliberate differences

- Claude is invoked through the local Claude Code executable because there is
  no official Java Agent SDK equivalent to the Python SDK used by the original.
- The Supervisor can use only Agent/Read/Glob/Grep. Native Hunter Subagents can
  use only Read/Glob/Grep. Java retains control of CodeQL and locks.
- The active workflow does not invoke CodeQL. Java prepares candidate call
  paths; Claude validates controllability, security checks and exploitability.

## Remaining production work

- Persist jobs and logs in a database; the current store is in memory.
- Add restart recovery for running jobs.
- Add authentication, authorization and upload quotas.
- Add Servlet, RPC, MQ and framework-specific `EntryPointDiscoverer` plugins.
- Add bytecode call-graph fallback for missing or syntactically damaged source.
- Add end-to-end audit fixtures that exercise real Claude credentials.
