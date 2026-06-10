# Code Audit System Java 21

Independent Java 21 refactor of `code-audit-system`.

## Runtime model

- Spring Boot 3.5
- Java 21 virtual threads
- LangChain4j 1.16.1 intelligent Orchestrator
- LangGraph4j 1.8.17 state graph
- One Claude Code Supervisor process per audit
- Native Claude Code Hunter Subagents inside the Supervisor session
- At most 15 concurrent CodeQL evidence preparation tasks
- CodeQL queries serialized per database with external file locks
- SSE-compatible API and static frontend
- Claude integration through the local `claude` CLI

## Intelligent Orchestrator

```text
Java prepares CodeQL evidence
            |
            v
LangGraph4j prepare_evidence
            |
            v
one Claude Code Supervisor process
            |
            +--> native audit-sql-injection Subagent
            +--> native audit-ssrf Subagent
            +--> native audit-... Subagents
            |
            v
LangGraph4j finalize
```

Only the Supervisor starts Claude Code. Specialist Hunters are native Claude
Code Subagents inside that session; Java no longer starts one CLI process per
Hunter. The Supervisor and Subagents cannot invoke Bash or CodeQL.

Set `INTELLIGENT_ORCHESTRATOR_ENABLED=false` to require delegation to all
available Subagents instead of model-selected specialists.

## Run

```powershell
$env:JAVA_HOME = "E:\Softwares\jdk-21.0.10+7"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
mvn spring-boot:run
```

The service listens on `http://localhost:8000`.

Optional executable overrides:

```powershell
$env:CODEQL_BIN = "D:\tools\codeql\codeql.exe"
$env:CLAUDE_BIN = "C:\tools\claude.exe"
```

When `CLAUDE_BIN` is not set, the service also searches PATH and the standard
Winget Claude Code package directory. CodeQL is searched on PATH and in the
common sibling layout `..\codeql\codeql\codeql.exe`.
