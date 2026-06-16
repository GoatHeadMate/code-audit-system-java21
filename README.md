# Code Audit System Java 21

Java 21 white-box source audit service for Java applications.

## Runtime model

- Spring Boot 3.5
- Java 21 virtual threads
- LangChain4j 1.16.1 intelligent Orchestrator
- LangGraph4j 1.8.17 state graph
- Python Claude Agent SDK Sidecar
- One Claude Supervisor session with native Hunter Subagents per audit
- Pluggable external entrypoint discoverers
- JDK compiler AST index for methods, calls, interface implementations and sinks
- Bounded entrypoint-to-sink candidate paths for Claude semantic review
- Stored-flow candidates joining HTTP writes to asynchronous execution paths
- Coverage metrics for binding, parser diagnostics and unresolved calls
- SSE-compatible API and static frontend
- HTTP/NDJSON integration between Java and the Python Sidecar

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
Python Claude Agent SDK Sidecar
            |
            +--> native audit-sql-injection Subagent
            +--> native audit-ssrf Subagent
            +--> native audit-... Subagents
            |
            v
LangGraph4j finalize
```

The Sidecar starts one Supervisor session. Specialist Hunters are native Claude
Subagents inside that session. Java owns broad, reproducible discovery:
entrypoints, method indexing, approximate dispatch, interface implementations,
dangerous sinks and candidate paths. Each Hunter receives only bounded paths
for its vulnerability category.

Claude validates attacker controllability, sanitizers, authentication,
authorization, framework dispatch, stored/asynchronous flows and exploit
conditions. It uses Read, Glob and Grep only to resolve missing evidence instead
of performing an unbounded repository-wide scan.

Stored-flow analysis records Repository, DAO, mapper, JDBC, Redis, Mongo and
similar read/write events. It builds an HTTP-to-write path and joins it to a
scheduled, message, event or async entrypoint-to-sink path. A matching storage
component is candidate evidence only; Claude must confirm the exact entity
field, column, cache key or mapper property before reporting a vulnerability.

`EntryPointDiscoverer` is the extension point for protocol/framework adapters.
The built-in discoverers support Spring MVC, JAX-RS and Huawei ROA HTTP
annotations plus Spring scheduled, async, event, Kafka, JMS and Rabbit listener
methods. Servlet and RPC discoverers can be added without changing the
call-graph or Claude layers.

The call graph is source-level and intentionally conservative. Unresolved calls,
parser diagnostics and unbound entrypoints are reported as coverage limitations;
they are never interpreted as proof that the project is safe.

The active workflow is implemented by the JDK compiler AST index and Claude
semantic review. It does not require an external static-analysis database.

Set `INTELLIGENT_ORCHESTRATOR_ENABLED=false` to require delegation to all
available Subagents instead of model-selected specialists.

## Run

Start the Python Sidecar first:

```powershell
cd sidecar
$env:UV_CACHE_DIR = "$PWD\.uv-cache"
$env:CLAUDE_SIDECAR_API_TOKEN = "replace-with-a-local-secret"
uv sync
uv run python -m claude_audit_sidecar
```

The Sidecar listens only on `http://127.0.0.1:8011` by default. It uses the
credentials supported by the installed Claude Agent SDK environment.

Start the Java service in another terminal:

```powershell
$env:JAVA_HOME = "E:\Softwares\jdk-21.0.10+7"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
$env:CLAUDE_SIDECAR_URL = "http://127.0.0.1:8011"
$env:CLAUDE_SIDECAR_TOKEN = "replace-with-a-local-secret"
mvn spring-boot:run
```

The service listens on `http://localhost:8000`.
