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
import io.agentscope.harness.agent.subagent.SubagentDeclaration;
import io.agentscope.harness.agent.subagent.WorkspaceMode;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import org.springframework.stereotype.Component;

@Component
public class AgentScopeGateway implements ClaudeGateway {
    private static final String USER_ID = "code-audit";

    private final AgentScopeProperties properties;

    public AgentScopeGateway(AgentScopeProperties properties) {
        this.properties = properties;
    }

    @Override
    public String query(Path workingDirectory, String prompt, Duration timeout) {
        try (HarnessAgent agent = baseBuilder(workingDirectory, List.of())
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
        List<SubagentDeclaration> declarations = buildSubagents(agents);
        AgentScopeEventCollector events = new AgentScopeEventCollector(
                eventConsumer
        );

        try (HarnessAgent agent = baseBuilder(workingDirectory, declarations)
                .name("audit-supervisor")
                .description("White-box security audit supervisor")
                .sysPrompt(supervisorPrompt(sourceRoot, declarations))
                .build()) {
            RuntimeContext context = runtimeContext("supervisor");
            agent.streamEvents(new UserMessage(prompt), context)
                    .doOnNext(events::handle)
                    .blockLast(properties.timeout());
        }
        events.flushAll();
        String result = events.finalResult();

        if (result.isBlank()) {
            throw new IllegalStateException(
                    "AgentScope supervisor returned no final JSON result"
            );
        }
        return result;
    }

    @Override
    public boolean available() {
        return properties.configured();
    }

    private HarnessAgent.Builder baseBuilder(
            Path workingDirectory,
            List<SubagentDeclaration> subagents
    ) {
        return HarnessAgent.builder()
                .model(model())
                .workspace(workingDirectory.toAbsolutePath().normalize())
                .maxIters(properties.maxIters())
                .subagents(subagents)
                .disableShellTool()
                .disableDynamicSkills()
                .disableDefaultWorkspaceSkills()
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
                .map(entry -> SubagentDeclaration.builder()
                        .name(entry.getKey())
                        .description(entry.getValue().description())
                        .inlineAgentsBody(entry.getValue().prompt())
                        .workspaceMode(WorkspaceMode.SHARED)
                        .steps(Math.min(properties.maxIters(), 30))
                        .mode(SubagentDeclaration.Mode.SUBAGENT)
                        .build())
                .toList();
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

    private String supervisorPrompt(
            Path sourceRoot,
            List<SubagentDeclaration> declarations
    ) {
        String subagentNames = declarations.stream()
                .map(SubagentDeclaration::getName)
                .reduce((left, right) -> left + ", " + right)
                .orElse("(none)");
        return """
                You are the Java AgentScope supervisor for a white-box security audit.
                Work autonomously. Your first action must be one or more agent_spawn
                tool calls that delegate selected evidence packages to registered
                hunter subagents when their category is relevant.
                Do not use list_files, read_file, glob_files, grep_files, memory_search,
                or other direct source-discovery tools as the supervisor. The registered
                hunter subagents perform source review.
                Do not use background, async, fire-and-forget, or timeout_seconds=0
                subagent calls. Every agent_spawn call must wait for a returned result with a
                non-zero timeout before you continue.
                Never finish immediately after scheduling hunters. Read every selected
                subagent result, then synthesize the final answer.
                Source root: %s
                Available hunter subagents: %s
                The final assistant message must be exactly one JSON object with fields:
                selected_hunters, rationale, findings.
                Do not include prose outside that final JSON object.
                """.formatted(
                sourceRoot.toAbsolutePath().normalize(),
                subagentNames
        );
    }

}
