package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class FindingConsolidatorTest {
    private final FindingConsolidator consolidator = new FindingConsolidator();

    @Test
    void mergesSameVulnerabilitySurfaceAcrossHunters() {
        List<Map<String, Object>> merged = consolidator.consolidate(List.of(
                finding("COMMAND_INJECTION", "/rce/runtime/exec",
                        "src/Rce.java", "cmdinj-exec-string",
                        "Runtime exec", "code_execution"),
                finding("COMMAND_INJECTION", "/rce/runtime/exec",
                        "src/Rce.java", "cmdinj-runtime",
                        "Runtime command execution", "general_review")
        ));

        assertThat(merged).singleElement().satisfies(finding -> {
            assertThat(finding)
                    .containsEntry("merged_count", 2)
                    .containsEntry("http_path", "/rce/runtime/exec");
            assertThat(strings(finding.get("merged_rule_ids")))
                    .containsExactlyInAnyOrder("cmdinj-exec-string", "cmdinj-runtime");
            assertThat(strings(finding.get("merged_hunters")))
                    .containsExactlyInAnyOrder("code_execution", "general_review");
        });
    }

    @Test
    void keepsDifferentEndpointSurfacesSeparate() {
        List<Map<String, Object>> merged = consolidator.consolidate(List.of(
                finding("COMMAND_INJECTION", "/rce/runtime/exec",
                        "src/Rce.java", "cmdinj-exec-string",
                        "Runtime exec", "code_execution"),
                finding("COMMAND_INJECTION", "/rce/ProcessBuilder",
                        "src/Rce.java", "cmdinj-procbuilder",
                        "ProcessBuilder exec", "code_execution")
        ));

        assertThat(merged).hasSize(2);
    }

    @Test
    void collapsesAttackChainVariantsByChainKind() {
        List<Map<String, Object>> merged = consolidator.consolidate(List.of(
                chain("attack-chain-unauth-rce",
                        "Unauthenticated RCE via permitAll command endpoints"),
                chain("authz-unauth-rce-chain",
                        "permitAll exposes SpEL and command execution RCE")
        ));

        assertThat(merged).singleElement().satisfies(finding -> {
            assertThat(finding)
                    .containsEntry("vuln_type", "ATTACK_CHAIN")
                    .containsEntry("merged_count", 2);
            assertThat(strings(finding.get("merged_rule_ids")))
                    .containsExactlyInAnyOrder(
                            "attack-chain-unauth-rce",
                            "authz-unauth-rce-chain"
                    );
        });
    }

    private Map<String, Object> finding(
            String type,
            String path,
            String file,
            String rule,
            String title,
            String hunter
    ) {
        return Map.of(
                "vuln_type", type,
                "http_path", path,
                "file_path", file,
                "rule_id", rule,
                "title", title,
                "severity", "CRITICAL",
                "verdict", "CONFIRM",
                "discovered_by", hunter
        );
    }

    private Map<String, Object> chain(String rule, String title) {
        return Map.of(
                "vuln_type", "ATTACK_CHAIN",
                "rule_id", rule,
                "title", title,
                "severity", "CRITICAL",
                "verdict", "CONFIRM",
                "http_path", "/rce/runtime/exec"
        );
    }

    private List<String> strings(Object value) {
        return ((List<?>) value).stream()
                .map(Object::toString)
                .toList();
    }
}
