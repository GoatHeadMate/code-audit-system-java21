package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.agent.impl.SubagentDefinitionServiceImpl;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import io.agentscope.core.skill.repository.FileSystemSkillRepository;
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
                .contains("description: >")
                .contains("Use this skill to validate candidate paths whose sink category is SQL execution")
                .contains("# SQL 注入判断知识");
        assertThat(Files.readString(skill))
                .doesNotContain("# White-Box Judgment Rules");
        assertThat(result).containsEntry("sql_injection", "audit-sql-injection");
        assertThat(tempDir.resolve(".claude/agents")).doesNotExist();
        assertThat(tempDir.resolve("instructions")).doesNotExist();
    }

    @Test
    void materializedSkillHasStableAgentScopeSkillId() throws Exception {
        new SubagentDefinitionServiceImpl().materialize(
                tempDir,
                List.of("sql_injection"),
                Map.of("sql_injection", "/path/to/task.json")
        );

        FileSystemSkillRepository repository = new FileSystemSkillRepository(
                tempDir.resolve(".claude/skills"),
                false,
                AgentScopeGateway.AUDIT_SKILL_SOURCE
        );

        assertThat(repository.getAllSkills())
                .extracting(skill -> skill.getSkillId())
                .containsExactly("audit-sql-injection_audit");
    }
}
