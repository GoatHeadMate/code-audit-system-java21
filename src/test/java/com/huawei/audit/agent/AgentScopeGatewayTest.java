package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AgentScopeGatewayTest {
    @Test
    void collectsEnabledSkillIdsForSubagentSkillCatalog() {
        Map<String, ClaudeGateway.AgentDef> agents = Map.of(
                "code_execution_team_general_endpoint_review",
                agent(Arrays.asList("audit-code-execution_audit", "", null)),
                "unsafe_parsing",
                agent(List.of("audit-unsafe-parsing_audit")),
                "unsafe_parsing_batch_1",
                agent(List.of("audit-unsafe-parsing_audit"))
        );

        assertThat(AgentScopeGateway.enabledSkillIds(agents))
                .containsExactly(
                        "audit-code-execution_audit",
                        "audit-unsafe-parsing_audit"
                );
    }

    @Test
    void returnsNoEnabledSkillsWhenAgentsDoNotDeclareSkills() {
        Map<String, ClaudeGateway.AgentDef> agents = Map.of(
                "code_execution",
                agent(null)
        );

        assertThat(AgentScopeGateway.enabledSkillIds(agents)).isEmpty();
    }

    private static ClaudeGateway.AgentDef agent(List<String> skills) {
        return new ClaudeGateway.AgentDef(
                "description",
                "prompt",
                List.of("read_file"),
                null,
                skills
        );
    }
}
