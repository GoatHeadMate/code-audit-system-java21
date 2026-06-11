package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.config.RuntimeExecutables;
import com.huawei.audit.process.ProcessResult;
import com.huawei.audit.process.ProcessRunner;
import dev.langchain4j.data.message.UserMessage;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ClaudeCodeSupervisorModelTest {

    @TempDir
    Path tempDir;

    @Test
    void logsReturnedSubagentNameProgressAndResultSize() throws Exception {
        RuntimeExecutables executables = mock(RuntimeExecutables.class);
        ProcessRunner processes = mock(ProcessRunner.class);
        when(executables.claude()).thenReturn("claude");
        when(processes.run(
                anyList(),
                any(Path.class),
                anyMap(),
                isNull(Duration.class),
                anyString(),
                any()
        )).thenAnswer(invocation -> {
            Consumer<String> output = invocation.getArgument(5);
            output.accept("""
                    {"type":"assistant","message":{"content":[{
                      "type":"tool_use",
                      "id":"agent-1",
                      "name":"Agent",
                      "input":{
                        "subagent_type":"audit-command-injection",
                        "description":"Review command execution paths"
                      }
                    }]}}
                    """);
            output.accept("""
                    {"type":"user","message":{"content":[{
                      "type":"tool_result",
                      "tool_use_id":"agent-1",
                      "content":"confirmed finding"
                    }]}}
                    """);
            output.accept("""
                    {"type":"result","result":"{\\"findings\\":[]}"}
                    """);
            return new ProcessResult(0, List.of());
        });

        ClaudeCodeSupervisorModel model = new ClaudeCodeSupervisorModel(
                executables,
                new OrchestratorProperties(true, 10, 5),
                processes,
                new ObjectMapper()
        );
        List<String> logs = new ArrayList<>();

        model.supervise(
                tempDir,
                tempDir,
                List.of(UserMessage.from("audit")),
                logs::add
        );

        assertThat(logs)
                .contains(
                        "[subagent-start] START audit-command-injection: "
                                + "Review command execution paths",
                        "[subagent-return] DONE audit-command-injection"
                                + " | progress 1/1 | result 17 B"
                );
    }
}
