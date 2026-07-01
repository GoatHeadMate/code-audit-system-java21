# 代码审计系统 Java 21 —— AgentScope 分支

Java 21 白盒代码审计服务。上传 ZIP 或指定 Git URL，系统先用静态分析挖出"外部入口 → 危险 sink"的候选攻击路径，再交给 LLM 监督者委派 8 类专项子代理逐条复核确认，产出带数据流路径的漏洞报告。前端是原生 HTML 单页应用，支持实时日志、漏洞展示、人工反馈和审计规则审批。

> 本 README 描述的是 **`AgentScope`** 分支。这个分支把早期"Python Claude Agent SDK sidecar"整个换成了**进程内**的 Java 集成；`master` 分支目前仍是旧的 sidecar + langgraph4j/langchain4j 架构，两者不能混用，见文末[与其他分支的关系](#与其他分支的关系)。

## 运行时构成

- Spring Boot 3.5，Java 21 虚拟线程
- JavaParser 3.26.2 —— 纯 AST 索引（方法、调用点、sink、入口），不依赖字节码、不需要外部数据库、不要求代码能成功编译
- 可选 JavaSymbolSolver 做精确调用图解析（默认关闭，见 [SYMBOL_SOLVER_说明.md](SYMBOL_SOLVER_说明.md)）
- **AgentScope Java Harness 2.0.0-RC4**（`io.agentscope:agentscope-harness`），进程内运行，不需要额外起 Python 进程
- 每个 hunter 类别对应一个独立的 AgentScope `HarnessAgent` 会话（原因见下面的 harness 工程章节）
- 可插拔的外部入口发现器（Servlet、WebFlux、异步/定时任务、JAX-RS、华为 ROA）
- 基于 JSONL 的审计记忆：把每次任务的 finding、人工/PoC 反馈沉淀成下次审计的先验、规则候选，经人工审批后回流生效
- SSE 实时日志 + 静态前端（无需构建步骤）

## 审计流程

```text
入口发现器 (Servlet / WebFlux / 异步 / JAX-RS / ROA)
        |
        v
JavaParser AST 索引：方法、调用点、危险 sink
        |
        v
调用图构建 + 传递性 sink 传播
        |
        v
入口 -> sink 有界候选路径 (BFS，按距离剪枝)
        |
        v
方法级污点摘要 + 校验
        |
        v
存储写入 / 异步执行 二段式候选关联
        |
        v
按 hunter 分包证据 + 生成判定 Skill
        |
        v
AgentScope 监督者
        |
        +--> audit-sql-injection 子代理  (独立 HarnessAgent 会话)
        +--> audit-ssrf 子代理           (独立 HarnessAgent 会话)
        +--> audit-... 子代理            (独立 HarnessAgent 会话)
        |
        v
跨 hunter 结果归并 -> 去重 -> 攻击链关联
        |
        v
findings.json + 统计 + 审计记忆更新
```

Java 一侧负责"广而可复现的发现"：入口、方法索引、近似调用分派、接口实现、危险 sink 和有界候选路径。每个 hunter 子代理只拿到与自己类别相关的候选，绝不做无边界的全仓库扫描。子代理只有只读工具（等价于 `Read`/`Glob`/`Grep`），负责从真实源码验证攻击者可控性、净化逻辑、鉴权、框架分派、存储/异步链路和利用条件——不重复做发现工作。

存储型链路分析会记录 Repository/DAO/Mapper/JDBC/Redis/Mongo 的读写事件，把 HTTP 写入路径和后续的定时/消息/事件/异步入口到 sink 的路径拼接起来。匹配上的存储组件只是候选证据，监督者必须确认具体的字段、列、缓存 key 或 mapper 属性,才能真正定性为漏洞。

调用图是源码级的，刻意保守。无法解析的调用、解析器诊断信息、未绑定的入口都作为覆盖度局限性上报（`CoverageCalculator`），从不当作"项目是安全的"的证据。`EntryPointDiscoverer` 是新增协议/框架适配器的扩展点，不需要改动调用图或 agent 层。

## Hunter 类别（8 类）

| 类别 | 覆盖范围 |
|---|---|
| `sql_injection` | SQL 注入（JDBC、MyBatis、JPA/Hibernate） |
| `ssrf` | 服务端请求伪造 |
| `authorization` | 鉴权缺失/薄弱 |
| `code_execution` | 命令注入 + SSTI |
| `unsafe_parsing` | 不安全反序列化 + XXE |
| `file_operations` | 文件上传 + 路径穿越 |
| `http_output` | XSS + CRLF 注入 + 开放重定向 |
| `component_vulns` | Actuator 暴露、H2 控制台 RCE、log4j JNDI |

`code_execution`、`authorization`、`unsafe_parsing`、`file_operations`、`ssrf`、`component_vulns` 只要有候选复核工作就必上；`HunterScheduler` 会按项目技术画像（ORM、序列化库、暴露组件）给其余类别加权排序。设置 `INTELLIGENT_ORCHESTRATOR_ENABLED=false` 可以强制委派全部有复核工作的 hunter,而不是由模型挑选专项。

## Harness 工程：AgentScope 是怎么接进来的

这个分支的核心改造是把 LLM 调用层从"Python sidecar 转发给 Claude Agent SDK"换成了进程内的 **AgentScope Java Harness**（commit `fc6b225`）。这不是简单换个 HTTP 客户端，而是有几层实打实的工程量：

### 1. 网关封装层（`agent/AgentScopeGateway.java`）

`ClaudeGateway` 接口（沿用旧名字保持调用方兼容）现在只有一个实现 `AgentScopeGateway`，把 `io.agentscope.harness.agent.HarnessAgent` 包了一层：

- **多 provider 路由**：`anthropic` / `openai` 兼容 / `dashscope`，按 `audit.agentscope.provider` 切换,分别构建 `AnthropicChatModel`/`OpenAIChatModel`/`DashScopeChatModel`。
- **过载重试**：命中 `overloaded`/`rate_limit`/`529` 等错误信号时自动退避重试（最多 2 次，30s/60s 递增等待）。
- **两级超时**：单次流式调用有 idle timeout（`AgentScopeProperties.idleTimeout`,默认 5 分钟,超过这个时间没有新事件就判定这个 hunter 会话失败）,还有独立于此的总超时。
- **权限收紧**：`disableShellTool()` / `disableSessionPersistence()` / `disableMemoryTools()`,子代理只能读文件,不能执行命令、不能写文件、不能用框架自带的长期记忆工具——保证审计过程不会改动被审代码。

### 2. 技能加载踩过的坑（`.debug-journal.md`,2026-06-30,本地调试日志）

子代理的判定知识以 Skill 形式提供（`hunter-prompts/audit-*.md` 物化成 `workDir/skills/audit-*/SKILL.md`）。接入初期,子代理拿到的 `skillId` 枚举是空的,技能根本加载不上。排查过程记录在 `.debug-journal.md`（已通过 `.git/info/exclude` 排除出版本库,是本地调试笔记）：

- **假设**：`SubagentDeclaration` 没有绑定 `AgentDef.skills`,或者生成的 skillId 和 harness 暴露的对不上。
- **根因定位**：`AgentScopeGateway` 建 harness 实例时调用了 `.disableDefaultWorkspaceSkills()`,把 harness 原生的 workspace 技能自动发现整个关掉了。
- **第一版方案（临时绕过，commit `992b8f6` + `1f929d9`）**：把生成好的 SKILL.md 内容直接内联进子代理的 prompt 字符串,不走技能加载机制。
- **真正修复（commit `bb0b68b`"改用 AgentScope 原生技能加载"）**：去掉 `.disableDefaultWorkspaceSkills()`,让 harness 按约定自动发现 `workDir/skills/*`,子代理 prompt 里恢复用 `load_skill_through_path(skillId, path="SKILL.md")` 作为第一步强制动作。

这是从"绕过去"走到"修根因"的完整闭环,不是留着workaround不管。

### 3. 事件流适配层（`agent/AgentScopeEventCollector.java` + `agent/AgentScopeTextBuffer.java`）

AgentScope 原生吐出来的是 `AgentEvent` 的各种子类型（`TextBlockDeltaEvent`、`ToolCallStartEvent`、`ToolResultEndEvent`、`AgentResultEvent`、`ExceedMaxItersEvent`）,需要专门翻译成本系统的 SSE 日志流：

- 文本增量按来源（supervisor / 各子代理）分别缓冲,攒够再 flush,避免日志被打得稀碎。
- 统计 `agent_spawn` 的启动/完成次数,用来识别"监督者其实根本没委派成功"这类静默失败（对应的空结果检测逻辑）。
- 监督者会话超出最大迭代数直接抛异常（视为致命错误）,子代理超迭代只记日志不中断整体审计。

这一层是跨好几个 commit 迭代出来的,不是一次到位：`660d265`(修复流式日志与空结果误判) → `7a2e668`(把事件处理从 Gateway 里拆成独立类,保留根因,同时补了专门的单测) → `8994870`(强制监督者必须吐合法 JSON) → `067b3b9`(修复漏洞发现页展示) → `b31622a`(文件工具限制升级到权限层) → `7780d6e`(修复子智能体编排与白盒缓存)。`AgentScopeEventCollectorTest` / `AgentScopeTextBufferTest` / `AgentScopePropertiesTest` 都是这几轮修复配的专项测试。

### 4. 从工程中暴露出来的框架约束

排查过程中发现 AgentScope 这个版本有一条硬限制：**一个 harness 会话里只能调用一次 `agent_spawn`**,第二次调用会触发框架级 fatal error。为此 `SupervisorAgent.superviseHunter` 改成给**每个 hunter 单独开一个 HarnessAgent 会话**（而不是一个监督者会话里管全部子代理）,靠 `Semaphore(MAX_PARALLEL_HUNTER_SESSIONS=2)` 硬编码限流并发数。这更像是绕开框架限制而不是理想设计,后续升级 AgentScope 版本时值得重新评估这条约束是否还存在。

## 审计记忆与反馈闭环

Finding 不是一次性产出。`JsonlAuditMemoryService` 把每次任务的 finding、人工/PoC 反馈、派生的规则候选都追加写入 `workspace/audit-memory/` 下的 JSONL 文件,SQLite 索引只加速查询,不作为真相源：

1. **召回只是先验,不是判决**——新任务的 hunter 会拿到相关历史 finding 和已批准规则作为上下文,但仍必须对着当前源码重新验证每一个候选才能确认。
2. **反馈**——前端和 `POST /audit/{jobId}/findings/auto-feedback` 支持 8 种 verdict（`CONFIRM`、`FALSE_POSITIVE`、`NEEDS_REVIEW`、`POC_SUCCESS`、`POC_FAILURE`、`DUPLICATE`、`RISK_DOWNGRADE`、`MISSED_FINDING`）,后者是给还没人复核的 finding 打保守自动评价的启发式评估器。
3. **规则候选**——重复出现的确认/误报模式会被提炼成规则候选（`GET /audit/rule-candidates`）,从不自动生效。
4. **人工 gate**——候选只有通过 `POST /audit/rule-candidates/{id}/decision` 才能变成已批准规则;已批准规则只提升后续 hunter 的复核优先级,仍然要从源码重新验证,不是自动判决。
5. **跨 hunter 归并**——去重之前,`FindingConsolidator` 会合并多个 hunter 报告的同一处漏洞面,保留置信度最高的版本,并记录被合并了哪些。

每一步都是只追加、可回滚的,这个闭环里没有任何环节能在无人决策的情况下悄悄压掉一个 finding。

## REST API（端口 8000）

| 方法与路径 | 作用 |
|---|---|
| `POST /audit` | 全量扫描（multipart `file` ZIP,或 `git_url`） |
| `POST /audit/interfaces` | 预扫描接口清单,不直接审计 |
| `POST /audit/{jobId}/start` | 只审计预扫描里勾选的接口 |
| `DELETE /audit/{jobId}/preview` | 取消一个废弃的预扫描任务 |
| `GET /audit` | 任务列表 |
| `GET /audit/{jobId}` | 任务状态 |
| `GET /audit/{jobId}/findings` | 漏洞列表（任务未完成时返回 `202`） |
| `POST /audit/{jobId}/findings/auto-feedback` | 对某任务的 finding 跑一遍自动评价 |
| `GET /audit/rule-candidates` | 待审批的规则候选列表 |
| `POST /audit/rule-candidates/{id}/decision` | 批准/拒绝/废弃某个规则候选 |
| `GET /audit/{jobId}/logs` | SSE 实时审计日志流 |
| `GET /health` | 健康检查 |

## 配置项

`audit.*` 下的配置键,大部分可以用环境变量覆盖：

| 环境变量 | 默认值 | 含义 |
|---|---|---|
| `AUDIT_WORKSPACE` | `workspace` | 任务工作目录与审计记忆的根目录 |
| `AGENTSCOPE_MAX_ITERS` | `80` | 每个 HarnessAgent 会话的最大迭代数（限制在 1-200） |
| `AGENTSCOPE_TIMEOUT` | `30m` | 单次会话超时 |
| `MAX_CONCURRENT_JOBS` | `2` | 并发审计任务数 |
| `MAX_CONCURRENT_HUNTERS` | `15` | 并发证据准备任务数（AgentScope hunter 会话本身另外硬编码限流到 2） |
| `HUNTER_TIMEOUT` | `30m` | 单个 hunter 会话超时 |
| `INTELLIGENT_ORCHESTRATOR_ENABLED` | `true` | 设为 `false` 强制委派全部有复核工作的 hunter |
| `MAX_PRIMARY_HUNTERS` / `MAX_ADDITIONAL_HUNTERS` | `10` / `5` | 模型自选 hunter 数量上限 |
| `MAX_CHUNKS_PER_BATCH` | `80` | 每个 hunter 批次的证据分块大小 |

### 模型 provider（`provider` / `model` / `api-key` / `base-url`）

和上面几项不一样,`audit.agentscope.provider`、`.model`、`.api-key`、`.base-url` 在这个分支的 `application.yml` 里**不是** `${环境变量:默认值}` 占位符,而是写死的字面量（当前指向一个非 Anthropic 的 provider,用于本地测试）。也就是说,直接设置 `AGENTSCOPE_PROVIDER` / `AGENTSCOPE_API_KEY` / `AGENTSCOPE_MODEL` 这几个环境变量**不会生效**（唯一的自动 env 兜底是 `AgentScopeProperties.effectiveApiKey()`,它只在 `audit.agentscope.api-key` 为空时才去读 provider 原生的 `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`/`DASHSCOPE_API_KEY`）。

不想改这个受版本控制的文件的话,可以用 Spring 的宽松绑定,带上完整属性路径：

```powershell
$env:AUDIT_AGENTSCOPE_PROVIDER = "anthropic"
$env:AUDIT_AGENTSCOPE_API_KEY = "换成你自己的本地密钥"
$env:AUDIT_AGENTSCOPE_MODEL = "claude-sonnet-4-5-20250929"
$env:AUDIT_AGENTSCOPE_BASE_URL = ""
```

这几个环境变量会覆盖 `application.yml` 里的值,因为 Spring Boot 的属性源优先级里,操作系统环境变量高于 classpath 配置文件。**不要把真实 API key 直接写进 `application.yml`**——这个字段已经泄露过一次真实密钥到工作区了;要么用上面的环境变量形式,要么把 yml 改成 `${AGENTSCOPE_API_KEY:}` 这种占位符,和同一个文件里 `max-iters`/`timeout` 的写法保持一致。

## 运行

```powershell
$env:JAVA_HOME = "E:\Softwares\jdk-21.0.10+7"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
$env:AUDIT_AGENTSCOPE_PROVIDER = "anthropic"
$env:AUDIT_AGENTSCOPE_API_KEY = "换成你自己的本地密钥"
$env:AUDIT_AGENTSCOPE_MODEL = "claude-sonnet-4-5-20250929"
mvn spring-boot:run
```

服务监听 `http://localhost:8000`,根路径 `/` 直接提供静态前端。这个分支不需要额外起 Python 进程。

```powershell
mvn test
```

跑单元/特征测试（JavaParser 索引、候选路径查找、AgentScope 网关与事件适配、审计记忆、结果归并、自动评价等）。

## 与其他分支的关系

- **`master`**——旧架构：Python FastAPI sidecar 跑 Claude Agent SDK,靠 langgraph4j 状态图编排。仍然能跑,但不是当前开发主力分支。它自己的 `审计系统全流程与技术说明.md` 详细描述的是这套架构,**不适用于本分支**。
- **`feat/external-interface-deep-audit`**——一个尚未合并的 Joern/CPG 尝试分支,面向"给定外部接口清单做深度扫描"的场景,和本分支的 AgentScope 集成无关。

## 已移除的技术（不要再加回来）

- **CodeQL**——早期版本用过,后来换成了 JavaParser 白盒方案。
- **Python Claude Agent SDK sidecar**——本分支已移除,换成进程内 AgentScope Java Harness（`master` 分支仍保留）。
- **langgraph4j / langchain4j**——本分支已移除,编排逻辑现在是普通的顺序 Java 调用（`IntelligentAuditGraph` 保留了类名以兼容调用方,但已经不是状态图库了）。
