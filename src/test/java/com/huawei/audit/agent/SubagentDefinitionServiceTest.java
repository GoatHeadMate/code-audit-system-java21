package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.agent.impl.SubagentDefinitionServiceImpl;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SubagentDefinitionServiceTest {

    @TempDir
    Path tempDir;

    @Test
    void materializesInstructionFiles() throws Exception {
        Map<String, String> result = new SubagentDefinitionServiceImpl().materialize(
                tempDir,
                List.of("sql_injection"),
                Map.of("sql_injection", "/path/to/task.json")
        );

        Path instruction = tempDir.resolve("instructions/audit-sql-injection.md");
        assertThat(instruction).isRegularFile();
        assertThat(Files.readString(instruction))
                .contains("sql_injection")
                .contains("Execution Contract")
                .contains("Category-Specific Judgment Rules")
                .contains("# SQL 注入判断知识");
        assertThat(result).containsKey("sql_injection");
        assertThat(result.get("sql_injection")).contains("audit-sql-injection.md");
        assertThat(tempDir.resolve(".claude/agents")).doesNotExist();
    }
}
