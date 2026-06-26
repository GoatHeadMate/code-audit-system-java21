package com.huawei.audit.agent;

import io.agentscope.core.event.AgentEvent;
import io.agentscope.core.event.AgentResultEvent;
import io.agentscope.core.event.ExceedMaxItersEvent;
import io.agentscope.core.event.TextBlockDeltaEvent;
import io.agentscope.core.event.ToolCallStartEvent;
import io.agentscope.core.event.ToolResultEndEvent;
import io.agentscope.core.message.ToolResultState;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

final class AgentScopeEventCollector {
    private static final String SUPERVISOR_SOURCE = "audit-supervisor";

    private final AtomicReference<String> result = new AtomicReference<>("");
    private final AtomicInteger completed = new AtomicInteger();
    private final Map<String, AgentScopeTextBuffer> buffers = new LinkedHashMap<>();
    private final Consumer<String> eventConsumer;

    AgentScopeEventCollector(Consumer<String> eventConsumer) {
        this.eventConsumer = eventConsumer;
    }

    void handle(AgentEvent event) {
        String source = source(event);
        switch (event.getType()) {
            case TEXT_BLOCK_DELTA -> {
                if (event instanceof TextBlockDeltaEvent text
                        && !text.getDelta().isBlank()) {
                    buffer(source).append(text.getDelta(), eventConsumer);
                }
            }
            case TOOL_CALL_START -> {
                buffer(source).flush(eventConsumer);
                if (event instanceof ToolCallStartEvent tool
                        && isSupervisor(source)
                        && "agent_spawn".equals(tool.getToolCallName())) {
                    eventConsumer.accept("[subagent-start] START agent_spawn");
                }
            }
            case TOOL_RESULT_END -> {
                buffer(source).flush(eventConsumer);
                if (event instanceof ToolResultEndEvent tool
                        && isSupervisor(source)
                        && "agent_spawn".equals(tool.getToolCallName())) {
                    int count = completed.incrementAndGet();
                    eventConsumer.accept("[subagent-return] "
                            + status(tool.getState())
                            + " agent_spawn | completed " + count);
                }
            }
            case AGENT_RESULT -> {
                buffer(source).flush(eventConsumer);
                if (event instanceof AgentResultEvent agentResult
                        && isSupervisor(source)) {
                    result.set(agentResult.getResult().getTextContent());
                }
            }
            case EXCEED_MAX_ITERS -> {
                buffer(source).flush(eventConsumer);
                if (event instanceof ExceedMaxItersEvent maxIters) {
                    String message = "AgentScope exceeded max iterations: "
                            + maxIters.getCurrentIter()
                            + "/"
                            + maxIters.getMaxIters();
                    if (isSupervisor(source)) {
                        throw new IllegalStateException(message);
                    }
                    eventConsumer.accept(logPrefix(source) + " " + message);
                }
            }
            default -> {
            }
        }
    }

    void flushAll() {
        buffers.values().forEach(buffer -> buffer.flush(eventConsumer));
    }

    String finalResult() {
        if (!result.get().isBlank()) {
            return result.get();
        }
        return buffer(SUPERVISOR_SOURCE).transcript();
    }

    private AgentScopeTextBuffer buffer(String source) {
        String normalized = source.isBlank() ? SUPERVISOR_SOURCE : source;
        return buffers.computeIfAbsent(
                normalized,
                key -> new AgentScopeTextBuffer(logPrefix(key))
        );
    }

    private boolean isSupervisor(String source) {
        return source.isBlank() || SUPERVISOR_SOURCE.equals(source);
    }

    private String source(AgentEvent event) {
        String source = event.getSource();
        return source == null ? "" : source.strip();
    }

    private String status(ToolResultState state) {
        return state == ToolResultState.SUCCESS ? "DONE" : state.name();
    }

    private String logPrefix(String source) {
        String normalized = source.isBlank() ? "supervisor" : source;
        if (SUPERVISOR_SOURCE.equals(normalized)) {
            normalized = "supervisor";
        }
        return "[agentscope-" + normalized.replaceAll("[^A-Za-z0-9_.-]", "_") + "]";
    }
}
