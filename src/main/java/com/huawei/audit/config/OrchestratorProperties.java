package com.huawei.audit.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

@ConfigurationProperties(prefix = "audit.orchestrator")
public record OrchestratorProperties(
        boolean enabled,
        int maxPrimaryHunters,
        int maxAdditionalHunters,
        int maxChunksPerBatch,
        int maxHunterSessionsPerRound,
        int maxRounds,
        Duration maxTotalJobDuration,
        int maxParallelHunterSessions,
        Duration hunterSessionTimeout,
        Duration modelSlotTimeout
) {
    public OrchestratorProperties(
            boolean enabled,
            int maxPrimaryHunters,
            int maxAdditionalHunters,
            int maxChunksPerBatch
    ) {
        this(
                enabled,
                maxPrimaryHunters,
                maxAdditionalHunters,
                maxChunksPerBatch,
                24,
                5,
                Duration.ofHours(6),
                2,
                Duration.ofMinutes(12),
                Duration.ofMinutes(2)
        );
    }

    @ConstructorBinding
    public OrchestratorProperties {
        maxPrimaryHunters = clamp(maxPrimaryHunters, 3, 15, 10);
        maxAdditionalHunters = clamp(maxAdditionalHunters, 0, 15, 5);
        maxChunksPerBatch = clamp(maxChunksPerBatch, 20, 500, 80);
        maxHunterSessionsPerRound = clamp(maxHunterSessionsPerRound, 1, 100, 24);
        maxRounds = clamp(maxRounds, 1, 50, 5);
        maxTotalJobDuration = clampDuration(
                maxTotalJobDuration, Duration.ofMinutes(10),
                Duration.ofHours(24), Duration.ofHours(6));
        maxParallelHunterSessions = clamp(maxParallelHunterSessions, 1, 20, 2);
        hunterSessionTimeout = clampDuration(
                hunterSessionTimeout, Duration.ofMinutes(1),
                Duration.ofHours(2), Duration.ofMinutes(12));
        modelSlotTimeout = clampDuration(
                modelSlotTimeout, Duration.ofSeconds(10),
                Duration.ofMinutes(30), Duration.ofMinutes(2));
    }

    private static int clamp(int value, int min, int max, int fallback) {
        int effective = value <= 0 ? fallback : value;
        return Math.max(min, Math.min(max, effective));
    }

    private static Duration clampDuration(
            Duration value,
            Duration min,
            Duration max,
            Duration fallback
    ) {
        Duration effective = value == null || value.isZero() || value.isNegative()
                ? fallback
                : value;
        if (effective.compareTo(min) < 0) {
            return min;
        }
        if (effective.compareTo(max) > 0) {
            return max;
        }
        return effective;
    }
}
