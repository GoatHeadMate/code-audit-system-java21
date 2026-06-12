package com.huawei.audit.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AttackChainCorrelatorTest {

    @Test
    void correlatesSsrfAndCommandInjection() {
        var findings = List.of(
                Map.<String, Object>of(
                        "rule_id", "ssrf-1",
                        "vuln_type", "SSRF",
                        "file_path", "src/main/java/com/acme/Proxy.java",
                        "start_line", 10,
                        "confidence", 0.9
                ),
                Map.<String, Object>of(
                        "rule_id", "cmd-1",
                        "vuln_type", "COMMAND_INJECTION",
                        "file_path", "src/main/java/com/acme/Exec.java",
                        "start_line", 20,
                        "confidence", 0.9
                )
        );

        var chains = new AttackChainCorrelator().correlate(findings, "com.acme");

        assertThat(chains)
                .extracting(finding -> finding.get("rule_id"))
                .contains("chain-ssrf-cmdinj");
    }

    @Test
    void correlatesSsrfWhitelistBypassAndCommandInjection() {
        var findings = List.of(
                Map.<String, Object>of(
                        "rule_id", "ssrf-weak-contains",
                        "vuln_type", "SSRF",
                        "file_path", "src/main/java/com/acme/Proxy.java",
                        "start_line", 10,
                        "confidence", 0.85
                ),
                Map.<String, Object>of(
                        "rule_id", "cmd-1",
                        "vuln_type", "COMMAND_INJECTION",
                        "file_path", "src/main/java/com/acme/Exec.java",
                        "start_line", 20,
                        "confidence", 0.9
                )
        );

        var chains = new AttackChainCorrelator().correlate(findings, "com.acme");

        assertThat(chains)
                .extracting(finding -> finding.get("rule_id"))
                .contains("chain-ssrf-whitelist-cmdinj");
    }

    @Test
    void correlatesUnauthorizedActionAsMissingAuth() {
        var findings = List.of(
                Map.<String, Object>of(
                        "rule_id", "authz-1",
                        "vuln_type", "UNAUTHORIZED_ACTION",
                        "file_path", "src/main/java/com/acme/Admin.java",
                        "start_line", 5,
                        "confidence", 0.9
                ),
                Map.<String, Object>of(
                        "rule_id", "cmd-1",
                        "vuln_type", "COMMAND_INJECTION",
                        "file_path", "src/main/java/com/acme/Exec.java",
                        "start_line", 20,
                        "confidence", 0.9
                )
        );

        var chains = new AttackChainCorrelator().correlate(findings, "com.acme");

        assertThat(chains)
                .extracting(finding -> finding.get("rule_id"))
                .contains("chain-noauth-cmdinj");
    }
}
