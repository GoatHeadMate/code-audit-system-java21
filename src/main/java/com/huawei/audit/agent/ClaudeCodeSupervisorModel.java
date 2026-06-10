package com.huawei.audit.agent;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.config.RuntimeExecutables;
import com.huawei.audit.process.ProcessResult;
import com.huawei.audit.process.ProcessRunner;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.ModelProvider;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.springframework.stereotype.Component;

@Component
public class ClaudeCodeSupervisorModel implements ChatModel {
    private final RuntimeExecutables executables;
    private final OrchestratorProperties properties;
    private final ProcessRunner processes;
    private final ObjectMapper objectMapper;
    private final ThreadLocal<SessionContext> sessionContext = new ThreadLocal<>();

    public ClaudeCodeSupervisorModel(
            RuntimeExecutables executables,
            OrchestratorProperties properties,
            ProcessRunner processes,
            ObjectMapper objectMapper
    ) {
        this.executables = executables;
        this.properties = properties;
        this.processes = processes;
        this.objectMapper = objectMapper;
    }

    public String supervise(
            Path workingDirectory,
            Path sourceRoot,
            List<ChatMessage> messages,
            Consumer<String> eventConsumer
    ) {
        sessionContext.set(new SessionContext(
                workingDirectory,
                sourceRoot,
                eventConsumer
        ));
        try {
            return chat(messages).aiMessage().text();
        } finally {
            sessionContext.remove();
        }
    }

    @Override
    public ChatResponse doChat(ChatRequest request) {
        SessionContext context = sessionContext.get();
        if (context == null) {
            throw new IllegalStateException("Claude supervisor session context is missing");
        }

        String prompt = formatMessages(request.messages());
        try {
            AtomicReference<String> finalResult = new AtomicReference<>("");
            ProcessResult result = processes.run(
                    List.of(
                            executables.claude(),
                            "--print",
                            "--output-format", "stream-json",
                            "--verbose",
                            "--permission-mode", "bypassPermissions",
                            "--allowedTools", "Agent,Read,Glob,Grep",
                            "--disallowedTools",
                            "Bash,Write,Edit,NotebookEdit,WebFetch,WebSearch",
                            "--add-dir", context.sourceRoot().toString()
                    ),
                    context.workingDirectory(),
                    Map.of("CLAUDE_CODE_ENTRYPOINT", "langchain4j-supervisor"),
                    null,
                    prompt,
                    line -> consumeStreamEvent(context, finalResult, line)
            );
            if (result.exitCode() != 0) {
                throw new IOException(
                        "Claude Code supervisor exited with " + result.exitCode()
                );
            }
            String response = finalResult.get();
            if (response.isBlank()) {
                throw new IOException(
                        "Claude Code supervisor returned no final result"
                );
            }
            return ChatResponse.builder()
                    .aiMessage(AiMessage.from(response))
                    .modelName("claude-code-supervisor")
                    .build();
        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Claude Code supervisor invocation failed",
                    exception
            );
        }
    }

    @Override
    public ModelProvider provider() {
        return ModelProvider.ANTHROPIC;
    }

    private String formatMessages(List<ChatMessage> messages) {
        StringBuilder prompt = new StringBuilder();
        for (ChatMessage message : messages) {
            if (message instanceof SystemMessage system) {
                prompt.append("SYSTEM:\n").append(system.text());
            } else if (message instanceof UserMessage user) {
                prompt.append("USER:\n").append(user.singleText());
            } else if (message instanceof AiMessage assistant) {
                prompt.append("ASSISTANT:\n").append(assistant.text());
            } else {
                prompt.append(message);
            }
            prompt.append("\n\n");
        }
        return prompt.toString();
    }

    private void consumeStreamEvent(
            SessionContext context,
            AtomicReference<String> finalResult,
            String line
    ) {
        try {
            JsonNode event = objectMapper.readTree(line);
            String type = event.path("type").asText();
            if ("result".equals(type)) {
                finalResult.set(event.path("result").asText(""));
                return;
            }
            if ("user".equals(type)) {
                // Count how many subagents returned tool_result blocks.
                JsonNode content = event.path("message").path("content");
                if (!content.isArray()) return;
                long returned = 0;
                for (JsonNode block : content) {
                    if ("tool_result".equals(block.path("type").asText())) returned++;
                }
                if (returned > 0) {
                    context.eventConsumer().accept(
                            "[supervisor-agent] " + returned + " subagent(s) returned results"
                    );
                }
                return;
            }
            if (!"assistant".equals(type)) {
                return;
            }
            JsonNode content = event.path("message").path("content");
            if (!content.isArray()) {
                return;
            }
            for (JsonNode block : content) {
                String blockType = block.path("type").asText();
                if ("tool_use".equals(blockType)
                        && "Agent".equals(block.path("name").asText())) {
                    JsonNode input = block.path("input");
                    String agent = input.path("subagent_type").asText(
                            input.path("name").asText("hunter")
                    );
                    String description = input.path("description").asText("");
                    context.eventConsumer().accept(
                            "[supervisor-agent] delegated " + agent
                                    + (description.isBlank() ? "" : ": " + description)
                    );
                } else if ("text".equals(blockType)) {
                    String text = block.path("text").asText("").strip();
                    if (!text.isBlank()) {
                        String preview = text.length() > 300
                                ? text.substring(0, 300) + "…"
                                : text;
                        context.eventConsumer().accept(
                                "[supervisor] " + preview.replace("\n", " | ")
                        );
                    }
                }
            }
        } catch (Exception ignored) {
            // Ignore non-JSON diagnostic lines from the CLI.
        }
    }

    private record SessionContext(
            Path workingDirectory,
            Path sourceRoot,
            Consumer<String> eventConsumer
    ) { }
}
