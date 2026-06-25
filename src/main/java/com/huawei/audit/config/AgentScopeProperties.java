package com.huawei.audit.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "audit.agentscope")
public record AgentScopeProperties(
        String provider,
        String model,
        String apiKey,
        String baseUrl,
        int maxIters,
        Duration timeout
) {
    public AgentScopeProperties {
        provider = blankDefault(provider, "anthropic").toLowerCase();
        model = blankDefault(model, "claude-sonnet-4-5-20250929");
        apiKey = apiKey == null ? "" : apiKey.strip();
        baseUrl = baseUrl == null ? "" : baseUrl.strip();
        maxIters = maxIters <= 0 ? 80 : Math.min(maxIters, 200);
        timeout = timeout == null ? Duration.ofMinutes(30) : timeout;
    }

    public boolean configured() {
        return !effectiveApiKey().isBlank();
    }

    public String effectiveApiKey() {
        if (!apiKey.isBlank()) {
            return apiKey;
        }
        return switch (provider) {
            case "openai" -> env("OPENAI_API_KEY");
            case "dashscope" -> env("DASHSCOPE_API_KEY");
            default -> env("ANTHROPIC_API_KEY");
        };
    }

    private static String blankDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.strip();
    }

    private static String env(String name) {
        String value = System.getenv(name);
        return value == null ? "" : value.strip();
    }
}
