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
    void materializesSkillFiles() throws Exception {
        Map<String, String> result = new SubagentDefinitionServiceImpl().materialize(
                tempDir,
                List.of("sql_injection"),
                Map.of("sql_injection", "/path/to/task.json")
        );

        Path skill = tempDir.resolve(".claude/skills/audit-sql-injection/SKILL.md");
        assertThat(skill).isRegularFile();
        assertThat(Files.readString(skill))
                .contains("name: audit-sql-injection")
                .contains("description:")
                .contains("White-Box Judgment Rules")
                .contains("# SQL 注入判断知识");
        assertThat(result).containsEntry("sql_injection", "audit-sql-injection");
        assertThat(tempDir.resolve(".claude/agents")).doesNotExist();
        assertThat(tempDir.resolve("instructions")).doesNotExist();
    }
}
