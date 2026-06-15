package com.huawei.audit.agent;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public interface ClaudeGateway {
    String query(Path workingDirectory, String prompt, Duration timeout);

    String supervise(
            Path workingDirectory,
            Path sourceRoot,
            String prompt,
            Map<String, AgentDef> agents,
            Consumer<String> eventConsumer
    );

    boolean available();

    record AgentDef(
            String description,
            String prompt,
            List<String> tools,
            String model
    ) {}
}
