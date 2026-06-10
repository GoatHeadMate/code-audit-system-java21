package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.hunter.FindingParser;
import com.huawei.audit.job.JobLogBroker;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SupervisorAgentTest {

    @Test
    void filtersDelegationToCandidateWhitelistAndMandatoryHunters()
            throws Exception {
        ClaudeCodeSupervisorModel model = mock(ClaudeCodeSupervisorModel.class);
        when(model.supervise(any(), any(), any(), any())).thenReturn("""
                {
                  "selected_hunters": ["ssrf", "not-a-real-agent"],
                  "rationale": "Spring HTTP client surface",
                  "findings": [{
                    "rule_id": "ssrf-1",
                    "severity": "HIGH",
                    "confidence": 0.9,
                    "file_path": "src/Test.java",
                    "start_line": 12,
                    "message": "User-controlled URL",
                    "vuln_type": "SSRF"
                  }]
                }
                """);

        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                model,
                objectMapper,
                new FindingParser(objectMapper),
                new OrchestratorProperties(
                        true,
                        Duration.ofMinutes(1),
                        4,
                        1
                ),
                new JobLogBroker()
        );
        AuditJob job = new AuditJob("super123", "java");
        job.workDir(Path.of("workspace", "audit_super123"));

        var result = supervisor.run(
                job,
                Path.of("source"),
                Map.of("web_framework", "Spring Boot"),
                List.of(
                        "sql_injection",
                        "command_injection",
                        "authorization",
                        "ssrf",
                        "xxe"
                ),
                Map.of()
        );

        assertThat(result.selectedHunters())
                .contains(
                        "sql_injection",
                        "command_injection",
                        "authorization",
                        "ssrf"
                )
                .doesNotContain("not-a-real-agent")
                .hasSizeLessThanOrEqualTo(5);
        assertThat(result.findings()).hasSize(1);
    }
}
