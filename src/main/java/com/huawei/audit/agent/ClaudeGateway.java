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
            Path workspace,
            List<String> tools,
            String model,
            Integer steps,
            int priority,
            String scheduleReason
    ) {
        public AgentDef(
                String description,
                String prompt,
                List<String> tools,
                String model
        ) {
            this(description, prompt, null, tools, model, null, 0, "");
        }
    }
}
