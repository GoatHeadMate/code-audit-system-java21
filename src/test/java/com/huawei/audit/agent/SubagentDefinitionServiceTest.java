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
                .contains("description: >")
                .contains("Use this skill to validate candidate paths whose sink category is SQL execution")
                .contains("# SQL 注入判断知识")
                .contains("## Endpoint Review Surface")
                .contains("poc_plan")
                .contains("STATIC_POC_PLAN_ONLY");
        assertThat(Files.readString(skill))
                .doesNotContain("# White-Box Judgment Rules");
        assertThat(result).containsEntry("sql_injection", "audit-sql-injection");
        assertThat(tempDir.resolve(".claude/agents")).doesNotExist();
        assertThat(tempDir.resolve("instructions")).doesNotExist();
    }

    @Test
    void dynamicTeamAndBatchNamesReuseBaseHunterSkill() throws Exception {
        Map<String, String> result = new SubagentDefinitionServiceImpl().materialize(
                tempDir,
                List.of(
                        "ssrf_team_ssrf",
                        "ssrf_team_ssrf_batch_1"
                ),
                Map.of(
                        "ssrf_team_ssrf", "/path/to/task.json",
                        "ssrf_team_ssrf_batch_1", "/path/to/task-batch-1.json"
                )
        );

        assertThat(result).containsExactly(Map.entry("ssrf", "audit-ssrf"));
        assertThat(tempDir.resolve(".claude/skills/audit-ssrf/SKILL.md"))
                .isRegularFile();
    }
}
