package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SubagentDefinitionServiceTest {

    @TempDir
    Path tempDir;

    @Test
    void materializesReadOnlyNativeClaudeSubagent() throws Exception {
        new SubagentDefinitionService().materialize(
                tempDir,
                List.of("sql_injection")
        );

        Path definition = tempDir.resolve(
                ".claude/agents/audit-sql-injection.md"
        );
        assertThat(definition).isRegularFile();
        assertThat(Files.readString(definition))
                .contains("tools: Read, Glob, Grep")
                .contains("disallowedTools: Bash, Write, Edit")
                .contains("Do not delegate to another agent");
    }
}
