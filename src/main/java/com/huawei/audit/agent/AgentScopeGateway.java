package com.huawei.audit.agent;

import com.huawei.audit.config.AgentScopeProperties;
import io.agentscope.core.agent.RuntimeContext;
import io.agentscope.core.message.Msg;
import io.agentscope.core.message.UserMessage;
import io.agentscope.core.model.AnthropicChatModel;
import io.agentscope.core.model.DashScopeChatModel;
import io.agentscope.core.model.Model;
import io.agentscope.core.model.OpenAIChatModel;
import io.agentscope.harness.agent.HarnessAgent;
import io.agentscope.harness.agent.filesystem.spec.LocalFilesystemSpec;
import io.agentscope.harness.agent.subagent.SubagentDeclaration;
import io.agentscope.harness.agent.subagent.WorkspaceMode;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class AgentScopeGateway implements ClaudeGateway {
    private static final Logger LOGGER = LoggerFactory.getLogger(
            AgentScopeGateway.class
    );
    private static final String USER_ID = "code-audit";
    private static final int MAX_RETRIES = 2;
    private static final long RETRY_BASE_DELAY_MS = 30_000L;

    private final AgentScopeProperties properties;

    public AgentScopeGateway(AgentScopeProperties properties) {
        this.properties = properties;
    }

    @Override
    public String query(Path workingDirectory, String prompt, Duration timeout) {
        try (HarnessAgent agent = baseBuilder(workingDirectory, workingDirectory, List.of())
                .name("audit-query-agent")
                .description("One-shot audit helper")
                .sysPrompt("Answer the audit question directly and return only the requested text.")
                .disableSubagents()
                .build()) {
            Msg response = agent.call(
                    new UserMessage(prompt),
                    runtimeContext("query")
            ).block(effectiveTimeout(timeout));
            if (response == null || response.getTextContent().isBlank()) {
                throw new IllegalStateException("AgentScope query returned no result");
            }
            return response.getTextContent();
        }
    }

    @Override
    public String supervise(
            Path workingDirectory,
            Path sourceRoot,
            String prompt,
            Map<String, AgentDef> agents,
            Consumer<String> eventConsumer
    ) {
        for (int attempt = 1; ; attempt++) {
            try {
                String result = doSupervise(
                        workingDirectory, sourceRoot, prompt, agents, eventConsumer
                );
                if (isOverloadedResponse(result) && attempt <= MAX_RETRIES) {
                    retryWait(attempt, eventConsumer);
                    continue;
                }
                return result;
            } catch (Exception exception) {
                if (attempt > MAX_RETRIES || !isRetryable(exception)) {
                    throw exception instanceof RuntimeException re
                            ? re
                            : new RuntimeException(exception);
                }
                retryWait(attempt, eventConsumer);
            }
        }
    }

    private String doSupervise(
            Path workingDirectory,
            Path sourceRoot,
            String prompt,
            Map<String, AgentDef> agents,
            Consumer<String> eventConsumer
    ) {
        List<SubagentDeclaration> declarations = buildSubagents(agents);
        AgentScopeEventCollector events = new AgentScopeEventCollector(
                eventConsumer
        );

        try (HarnessAgent agent = baseBuilder(workingDirectory, sourceRoot, declarations)
                .name("audit-supervisor")
                .description("White-box security audit supervisor")
                .sysPrompt("You are a white-box security audit supervisor. Follow the user prompt exactly.")
                .disableMemoryTools()
                .build()) {
            RuntimeContext context = runtimeContext("supervisor");
            agent.streamEvents(new UserMessage(prompt), context)
                    .doOnNext(events::handle)
                    .timeout(properties.idleTimeout())
                    .doOnError(TimeoutException.class, error ->
                            eventConsumer.accept("[supervisor-agent] AgentScope idle timeout after "
                                    + properties.idleTimeout()
                                    + " without stream events; failing this hunter session"))
                    .blockLast(supervisorTotalTimeout(declarations));
        } finally {
            events.flushAll();
        }
        String result = events.finalResult();

        if (result.isBlank()) {
            String detail = events.startedAgentSpawns() > 0
                    ? "started " + events.startedAgentSpawns()
                            + " agent_spawn(s), completed "
                            + events.completedAgentSpawns()
                    : "no agent_spawn calls observed";
            throw new IllegalStateException(
                    "AgentScope supervisor returned no final JSON result ("
                            + detail + ")"
            );
        }
        return result;
    }

    private boolean isRetryable(Exception exception) {
        for (Throwable t = exception; t != null; t = t.getCause()) {
            String msg = t.getMessage();
            if (msg != null && (msg.contains("overloaded")
                    || msg.contains("rate_limit")
                    || msg.contains("过大")
                    || msg.contains("529"))) {
                return true;
            }
        }
        return false;
    }

    private boolean isOverloadedResponse(String result) {
        return result.contains("overloaded_error")
                || result.contains("rate_limit_error");
    }

    private void retryWait(int attempt, Consumer<String> eventConsumer) {
        long delay = RETRY_BASE_DELAY_MS * attempt;
        eventConsumer.accept(
                "[supervisor] API 过载，" + (delay / 1000)
                        + "s 后重试 (第 " + (attempt + 1) + " 次)"
        );
        LOGGER.warn("API overloaded, retrying in {}s (attempt {}/{})",
                delay / 1000, attempt + 1, MAX_RETRIES + 1);
        try {
            Thread.sleep(delay);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Retry interrupted", interrupted);
        }
    }

    @Override
    public boolean available() {
        return properties.configured();
    }

    private HarnessAgent.Builder baseBuilder(
            Path workingDirectory,
            Path projectRoot,
            List<SubagentDeclaration> subagents
    ) {
        Path workspace = workingDirectory.toAbsolutePath().normalize();
        Path project = (projectRoot == null ? workingDirectory : projectRoot)
                .toAbsolutePath()
                .normalize();
        return HarnessAgent.builder()
                .model(model())
                .workspace(workspace)
                .filesystem(new LocalFilesystemSpec()
                        .project(project)
                        .addRoot(workspace))
                .maxIters(properties.maxIters())
                .subagents(subagents)
                .disableShellTool()
                .disableSessionPersistence();
    }

    private Model model() {
        String apiKey = properties.effectiveApiKey();
        return switch (properties.provider()) {
            case "openai" -> openAiModel(apiKey);
            case "dashscope" -> dashScopeModel(apiKey);
            case "anthropic" -> anthropicModel(apiKey);
            default -> throw new IllegalStateException(
                    "Unsupported AgentScope provider: " + properties.provider()
            );
        };
    }

    private Model anthropicModel(String apiKey) {
        AnthropicChatModel.Builder builder = AnthropicChatModel.builder()
                .apiKey(apiKey)
                .modelName(properties.model())
                .stream(true);
        if (!properties.baseUrl().isBlank()) {
            builder.baseUrl(properties.baseUrl());
        }
        return builder.build();
    }

    private Model openAiModel(String apiKey) {
        OpenAIChatModel.Builder builder = OpenAIChatModel.builder()
                .apiKey(apiKey)
                .modelName(properties.model())
                .stream(true);
        if (!properties.baseUrl().isBlank()) {
            builder.baseUrl(properties.baseUrl());
        }
        return builder.build();
    }

    private Model dashScopeModel(String apiKey) {
        DashScopeChatModel.Builder builder = DashScopeChatModel.builder()
                .apiKey(apiKey)
                .modelName(properties.model())
                .stream(true);
        if (!properties.baseUrl().isBlank()) {
            builder.baseUrl(properties.baseUrl());
        }
        return builder.build();
    }

    private List<SubagentDeclaration> buildSubagents(Map<String, AgentDef> agents) {
        if (agents == null || agents.isEmpty()) {
            return List.of();
        }
        return agents.entrySet().stream()
                .map(entry -> {
                    SubagentDeclaration.Builder builder = SubagentDeclaration.builder()
                            .name(entry.getKey())
                            .description(entry.getValue().description())
                            .steps(effectiveSteps(entry.getValue()))
                            .mode(SubagentDeclaration.Mode.SUBAGENT);
                    Path definitionWorkspace = entry.getValue().workspace();
                    if (definitionWorkspace != null) {
                        builder.workspace(definitionWorkspace.toAbsolutePath().normalize())
                                .workspaceMode(WorkspaceMode.ISOLATED);
                    } else {
                        builder.inlineAgentsBody(entry.getValue().prompt())
                                .workspaceMode(WorkspaceMode.SHARED);
                    }
                    List<String> tools = entry.getValue().tools();
                    if (tools != null && !tools.isEmpty()) {
                        builder.tools(tools);
                    }
                    return builder.build();
                })
                .toList();
    }

    private int effectiveSteps(AgentDef agentDef) {
        int requested = agentDef.steps() == null ? 30 : agentDef.steps();
        return Math.max(8, Math.min(properties.maxIters(), requested));
    }

    private RuntimeContext runtimeContext(String prefix) {
        return RuntimeContext.builder()
                .userId(USER_ID)
                .sessionId(prefix + "-" + UUID.randomUUID())
                .build();
    }

    private Duration effectiveTimeout(Duration requested) {
        return requested == null ? properties.timeout() : requested;
    }

    private Duration supervisorTotalTimeout(List<SubagentDeclaration> declarations) {
        int subagentCount = declarations == null ? 0 : declarations.size();
        int multiplier = Math.max(1, Math.min(subagentCount, 8));
        return properties.timeout().multipliedBy(multiplier);
    }

}
