# Code Audit System Java 21

Java 21 white-box source audit service for Java applications.

## Runtime model

- Spring Boot 3.5
- Java 21 virtual threads
- LangChain4j 1.16.1 intelligent Orchestrator
- LangGraph4j 1.8.17 state graph
- AgentScope Java Harness 2.0.0-RC4
- One AgentScope Supervisor session with Hunter Subagents per audit
- Pluggable external entrypoint discoverers
- JDK compiler AST index for methods, calls, interface implementations and sinks
- Bounded entrypoint-to-sink candidate paths for AgentScope semantic review
- Stored-flow candidates joining HTTP writes to asynchronous execution paths
- Coverage metrics for binding, parser diagnostics and unresolved calls
- SSE-compatible API and static frontend
- In-process Java AgentScope integration

## Candidate-path white-box audit

```text
entrypoint discoverers
        |
        v
JDK AST method/call/sink index
        |
        v
bounded entrypoint -> sink paths
            |
            v
LangGraph4j prepare_evidence
            |
            v
AgentScope Java Harness
            |
            +--> audit-sql-injection Subagent
            +--> audit-ssrf Subagent
            +--> audit-... Subagents
            |
            v
LangGraph4j finalize
```

AgentScope starts one Supervisor session. Specialist Hunters are AgentScope
Subagents inside that session. Java owns broad, reproducible discovery:
entrypoints, method indexing, approximate dispatch, interface implementations,
dangerous sinks and candidate paths. Each Hunter receives only bounded paths
for its vulnerability category.

AgentScope validates attacker controllability, sanitizers, authentication,
authorization, framework dispatch, stored/asynchronous flows and exploit
conditions. It uses Read, Glob and Grep only to resolve missing evidence instead
of performing an unbounded repository-wide scan.

Stored-flow analysis records Repository, DAO, mapper, JDBC, Redis, Mongo and
similar read/write events. It builds an HTTP-to-write path and joins it to a
scheduled, message, event or async entrypoint-to-sink path. A matching storage
component is candidate evidence only; AgentScope must confirm the exact entity
field, column, cache key or mapper property before reporting a vulnerability.

`EntryPointDiscoverer` is the extension point for protocol/framework adapters.
The built-in discoverers support Spring MVC, JAX-RS and Huawei ROA HTTP
annotations plus Spring scheduled, async, event, Kafka, JMS and Rabbit listener
methods. Servlet and RPC discoverers can be added without changing the
call-graph or agent layers.

The call graph is source-level and intentionally conservative. Unresolved calls,
parser diagnostics and unbound entrypoints are reported as coverage limitations;
they are never interpreted as proof that the project is safe.

The active workflow is implemented by the JDK compiler AST index and AgentScope
semantic review. It does not require an external static-analysis database.

Set `INTELLIGENT_ORCHESTRATOR_ENABLED=false` to require delegation to all
available Subagents instead of model-selected specialists.

## Run

Start the Java service:

```powershell
$env:JAVA_HOME = "E:\Softwares\jdk-21.0.10+7"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
$env:AGENTSCOPE_PROVIDER = "anthropic"
$env:AGENTSCOPE_API_KEY = "replace-with-a-local-secret"
$env:AGENTSCOPE_MODEL = "claude-sonnet-4-5-20250929"
mvn spring-boot:run
```

The service listens on `http://localhost:8000`. AgentScope also supports
OpenAI-compatible and DashScope providers through `AGENTSCOPE_PROVIDER`,
`AGENTSCOPE_BASE_URL`, and the matching API key environment variable.
