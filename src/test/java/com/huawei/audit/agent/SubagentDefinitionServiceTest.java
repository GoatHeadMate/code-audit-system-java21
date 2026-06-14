package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.agent.impl.SubagentDefinitionServiceImpl;
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
        new SubagentDefinitionServiceImpl().materialize(
                tempDir,
                List.of("sql_injection"),
                java.util.Map.of("sql_injection", "/path/to/task.json")
        );

        Path definition = tempDir.resolve(
                ".claude/agents/audit-sql-injection.md"
        );
        Path skill = tempDir.resolve(
                ".claude/skills/audit-sql-injection/SKILL.md"
        );
        assertThat(definition).isRegularFile();
        assertThat(Files.readString(definition))
                .contains("tools: Read, Glob, Grep")
                .contains("disallowedTools: Bash, Write, Edit")
                .contains("""
                        skills:
                          - audit-sql-injection
                        """)
                .contains("Do not delegate to another agent")
                .contains("EVERY candidate-path")
                .contains("/path/to/task.json");
        assertThat(skill).isRegularFile();
        assertThat(Files.readString(skill))
                .contains("name: audit-sql-injection")
                .contains("user-invocable: false")
                .contains("# SQL 注入判断知识");
        assertThat(tempDir.resolve("hunter-knowledge")).doesNotExist();
    }
}
