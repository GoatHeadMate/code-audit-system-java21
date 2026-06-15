package com.huawei.audit.agent;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.ModelProvider;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.springframework.stereotype.Component;

@Component
public class ClaudeAgentSupervisorModel implements ChatModel {
    private final ClaudeGateway gateway;
    private final ThreadLocal<SessionContext> sessionContext = new ThreadLocal<>();

    public ClaudeAgentSupervisorModel(ClaudeGateway gateway) {
        this.gateway = gateway;
    }

    public String supervise(
            Path workingDirectory,
            Path sourceRoot,
            List<ChatMessage> messages,
            Map<String, ClaudeGateway.AgentDef> agents,
            Consumer<String> eventConsumer
    ) {
        sessionContext.set(new SessionContext(
                workingDirectory,
                sourceRoot,
                agents,
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
            String response = gateway.supervise(
                    context.workingDirectory(),
                    context.sourceRoot(),
                    prompt,
                    context.agents(),
                    context.eventConsumer()
            );
            if (response.isBlank()) {
                throw new IllegalStateException(
                        "Claude Agent supervisor returned no final result"
                );
            }
            return ChatResponse.builder()
                    .aiMessage(AiMessage.from(response))
                    .modelName("claude-agent-sdk-supervisor")
                    .build();
        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Claude Agent supervisor invocation failed",
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

    private record SessionContext(
            Path workingDirectory,
            Path sourceRoot,
            Map<String, ClaudeGateway.AgentDef> agents,
            Consumer<String> eventConsumer
    ) { }
}
