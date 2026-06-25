# Migration Status

This project is independent from `D:\huawei\code-audit-system`.

## Implemented

- Java 21 and Spring Boot 3.5 runtime
- Existing REST paths and snake_case response contract
- ZIP and Git source ingestion
- Java `ProcessBuilder` integration for Git
- Maximum 15 concurrent hunters on virtual threads
- Pluggable entrypoint discovery with Spring MVC, JAX-RS and Huawei ROA support
- JDK compiler AST method, invocation, interface implementation and sink index
- Bounded entrypoint-to-sink candidate-path generation before AgentScope analysis
- Coverage reporting for entrypoint binding, parser diagnostics and unresolved calls
- Evidence size limits and partial query error isolation
- Technology profile, Hunter scheduling and finding normalization
- Finding deduplication and attack-chain correlation
- LangChain4j-backed intelligent Orchestrator decisions
- LangGraph4j state graph with evidence preparation, one Supervisor session and
  deterministic finalization
- Java AgentScope Harness integration
- AgentScope custom Subagents generated per audit job
- One AgentScope Supervisor session per audit job
- SSE log streaming
- Existing static frontend and 15 Hunter prompts

## Deliberate differences

- Java keeps ownership of AST analysis and orchestration while AgentScope Java
  runs the Supervisor and Hunter Subagents in-process.
- One-shot LLM enrichment and Supervisor sessions share one Java
  `ClaudeGateway` contract backed by `AgentScopeGateway`; no Java component
  invokes the Claude CLI or Python sidecar.
- The Supervisor delegates to AgentScope Hunter Subagents and inherited
  read-only workspace tools.
- Java prepares candidate call paths; AgentScope validates controllability,
  security checks and exploitability.

## Remaining production work

- Persist jobs and logs in a database; the current store is in memory.
- Add restart recovery for running jobs.
- Add authentication, authorization and upload quotas.
- Add Servlet, RPC, MQ and framework-specific `EntryPointDiscoverer` plugins.
- Add bytecode call-graph fallback for missing or syntactically damaged source.
- Add end-to-end audit fixtures that exercise real AgentScope provider credentials.
