package com.huawei.audit.config;

import java.nio.file.Path;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "audit")
public record AuditProperties(
        Path workspace,
        String codeqlBin,
        String claudeBin,
        int maxConcurrentJobs,
        int maxConcurrentHunters,
        Duration hunterTimeout,
        Duration queryLockTimeout
) {
    public AuditProperties {
        workspace = workspace == null ? Path.of("workspace") : workspace;
        codeqlBin = blankDefault(codeqlBin, "codeql");
        claudeBin = blankDefault(claudeBin, "claude");
        maxConcurrentJobs = clamp(maxConcurrentJobs, 1, 32, 2);
        maxConcurrentHunters = clamp(maxConcurrentHunters, 1, 15, 15);
        hunterTimeout = hunterTimeout == null ? Duration.ofMinutes(30) : hunterTimeout;
        queryLockTimeout = queryLockTimeout == null
                ? Duration.ofMinutes(30)
                : queryLockTimeout;
    }

    public Path absoluteWorkspace() {
        return workspace.toAbsolutePath().normalize();
    }

    private static String blankDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private static int clamp(int value, int min, int max, int fallback) {
        int effective = value <= 0 ? fallback : value;
        return Math.max(min, Math.min(max, effective));
    }
}
