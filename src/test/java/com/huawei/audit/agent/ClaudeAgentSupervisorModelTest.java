package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import dev.langchain4j.data.message.UserMessage;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ClaudeAgentSupervisorModelTest {

    @TempDir
    Path tempDir;

    @Test
    void delegatesFormattedPromptAndForwardsEvents() {
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        when(gateway.supervise(
                any(Path.class),
                any(Path.class),
                anyString(),
                any(),
                any()
        )).thenAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            var events = (java.util.function.Consumer<String>)
                    invocation.getArgument(4);
            events.accept("[subagent-start] START authorization");
            return "{\"findings\":[]}";
        });
        ClaudeAgentSupervisorModel model = new ClaudeAgentSupervisorModel(
                gateway
        );
        List<String> logs = new ArrayList<>();

        String response = model.supervise(
                tempDir,
                tempDir,
                List.of(UserMessage.from("audit")),
                java.util.Map.of(),
                logs::add
        );

        assertThat(response).isEqualTo("{\"findings\":[]}");
        assertThat(logs).containsExactly(
                "[subagent-start] START authorization"
        );
    }
}
