package com.huawei.audit.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "audit.orchestrator")
public record OrchestratorProperties(
        boolean enabled,
        Duration timeout,
        int maxPrimaryHunters,
        int maxAdditionalHunters
) {
    public OrchestratorProperties {
        timeout = timeout == null ? Duration.ofMinutes(3) : timeout;
        maxPrimaryHunters = clamp(maxPrimaryHunters, 3, 15, 10);
        maxAdditionalHunters = clamp(maxAdditionalHunters, 0, 15, 5);
    }

    private static int clamp(int value, int min, int max, int fallback) {
        int effective = value <= 0 ? fallback : value;
        return Math.max(min, Math.min(max, effective));
    }
}
