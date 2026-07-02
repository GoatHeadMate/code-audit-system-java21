package com.huawei.audit.config;

import java.nio.file.Path;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

@ConfigurationProperties(prefix = "audit")
public record AuditProperties(
        Path workspace,
        String claudeSidecarUrl,
        String claudeSidecarToken,
        Duration claudeSidecarTimeout,
        int maxConcurrentJobs,
        int maxConcurrentHunters,
        Duration hunterTimeout,
        boolean resumeOnStartup
) {
    @ConstructorBinding
    public AuditProperties {
        workspace = workspace == null ? Path.of("workspace") : workspace;
        claudeSidecarUrl = blankDefault(
                claudeSidecarUrl,
                "http://127.0.0.1:8011"
        );
        claudeSidecarToken = claudeSidecarToken == null
                ? ""
                : claudeSidecarToken.strip();
        claudeSidecarTimeout = claudeSidecarTimeout == null
                ? Duration.ofMinutes(30)
                : claudeSidecarTimeout;
        maxConcurrentJobs = clamp(maxConcurrentJobs, 1, 32, 2);
        maxConcurrentHunters = clamp(maxConcurrentHunters, 1, 15, 15);
        hunterTimeout = hunterTimeout == null ? Duration.ofMinutes(30) : hunterTimeout;
    }

    public AuditProperties(
            Path workspace,
            String claudeSidecarUrl,
            String claudeSidecarToken,
            Duration claudeSidecarTimeout,
            int maxConcurrentJobs,
            int maxConcurrentHunters,
            Duration hunterTimeout
    ) {
        this(
                workspace,
                claudeSidecarUrl,
                claudeSidecarToken,
                claudeSidecarTimeout,
                maxConcurrentJobs,
                maxConcurrentHunters,
                hunterTimeout,
                false
        );
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
