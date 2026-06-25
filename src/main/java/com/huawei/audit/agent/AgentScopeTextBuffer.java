package com.huawei.audit.agent;

import java.util.function.Consumer;

final class AgentScopeTextBuffer {
    private static final int MAX_LOG_CHARS = 240;
    private static final int PREVIEW_CHARS = 300;

    private final StringBuilder pending = new StringBuilder();
    private final StringBuilder transcript = new StringBuilder();

    void append(String delta, Consumer<String> eventConsumer) {
        transcript.append(delta);
        pending.append(delta);
        if (shouldFlush(delta)) {
            flush(eventConsumer);
        }
    }

    void flush(Consumer<String> eventConsumer) {
        String text = pending.toString().strip();
        pending.setLength(0);
        if (!text.isBlank()) {
            eventConsumer.accept("[agentscope-supervisor] " + preview(text));
        }
    }

    String transcript() {
        return transcript.toString().strip();
    }

    private boolean shouldFlush(String delta) {
        return delta.contains("\n")
                || pending.length() >= MAX_LOG_CHARS
                || endsWithSentencePunctuation(delta);
    }

    private boolean endsWithSentencePunctuation(String text) {
        String stripped = text.stripTrailing();
        if (stripped.isEmpty()) {
            return false;
        }
        char last = stripped.charAt(stripped.length() - 1);
        return last == '.'
                || last == '?'
                || last == '!'
                || last == '}'
                || last == ']'
                || last == '\u3002'
                || last == '\uff1f'
                || last == '\uff01';
    }

    private String preview(String text) {
        String flattened = text.replace("\n", " | ");
        return flattened.length() <= PREVIEW_CHARS
                ? flattened
                : flattened.substring(0, PREVIEW_CHARS) + "...";
    }
}
