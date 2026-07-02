package com.huawei.audit.config;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "audit.codegraph")
public record CodeGraphProperties(
        boolean enabled,
        String command,
        List<String> tools,
        boolean autoIndex,
        Duration initTimeout,
        Duration timeout,
        Duration initializationTimeout,
        String nodeHome
) {
    public CodeGraphProperties {
        command = command == null || command.isBlank()
                ? "codegraph"
                : command.strip();
        tools = normalizeTools(tools);
        initTimeout = positiveOrDefault(initTimeout, Duration.ofMinutes(2));
        timeout = positiveOrDefault(timeout, Duration.ofMinutes(2));
        initializationTimeout = positiveOrDefault(
                initializationTimeout, Duration.ofSeconds(30));
        nodeHome = nodeHome == null ? "" : nodeHome.strip();
    }

    public static CodeGraphProperties disabled() {
        return new CodeGraphProperties(
                false,
                "codegraph",
                List.of("codegraph_explore"),
                false,
                Duration.ofMinutes(2),
                Duration.ofMinutes(2),
                Duration.ofSeconds(30),
                ""
        );
    }

    /**
     * Machines whose system Node is incompatible with codegraph (it hard-refuses
     * to run on Node >=25, see colbymchenry/codegraph#81) can point this at a
     * directory containing a compatible Node binary instead of touching global
     * PATH/npm shims. Left blank, the child process resolves "node" exactly as
     * it does today.
     */
    public boolean hasNodeHome() {
        return !nodeHome.isEmpty();
    }

    public String mcpToolsEnvValue() {
        return String.join(",", tools.stream()
                .map(CodeGraphProperties::shortToolName)
                .toList());
    }

    private static List<String> normalizeTools(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of("codegraph_explore");
        }
        List<String> normalized = values.stream()
                .filter(value -> value != null && !value.isBlank())
                .map(String::strip)
                .map(CodeGraphProperties::fullToolName)
                .distinct()
                .toList();
        return normalized.isEmpty() ? List.of("codegraph_explore") : normalized;
    }

    private static String fullToolName(String value) {
        return value.startsWith("codegraph_") ? value : "codegraph_" + value;
    }

    private static String shortToolName(String value) {
        return value.startsWith("codegraph_")
                ? value.substring("codegraph_".length())
                : value;
    }

    private static Duration positiveOrDefault(Duration value, Duration fallback) {
        return value == null || value.isZero() || value.isNegative()
                ? fallback
                : value;
    }
}
