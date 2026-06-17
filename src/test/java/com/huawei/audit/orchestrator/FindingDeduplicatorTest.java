package com.huawei.audit.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class FindingDeduplicatorTest {

    @Test
    void keepsConfirmedFindingOverNeedsReviewForSameLocation() {
        var deduplicator = new FindingDeduplicator();
        var findings = List.of(
                finding("NEEDS_REVIEW", 0.95),
                finding("CONFIRM", 0.70)
        );

        var deduplicated = deduplicator.deduplicate(findings);
        var statistics = deduplicator.statistics(deduplicated);

        assertThat(deduplicated).hasSize(1);
        assertThat(deduplicated.getFirst())
                .containsEntry("verdict", "CONFIRM");
        assertThat(statistics)
                .containsKey("by_verdict");
    }

    private Map<String, Object> finding(String verdict, double confidence) {
        return Map.of(
                "rule_id", "authz-tenant-bypass",
                "file_path", "src/Admin.java",
                "start_line", 12,
                "severity", "HIGH",
                "confidence", confidence,
                "verdict", verdict,
                "discovered_by", "authorization",
                "vuln_type", "AUTHORIZATION"
        );
    }
}
