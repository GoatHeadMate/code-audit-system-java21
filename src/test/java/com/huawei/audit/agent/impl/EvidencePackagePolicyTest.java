package com.huawei.audit.agent.impl;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class EvidencePackagePolicyTest {
    @Test
    void mapsEveryConfiguredHunterToAtLeastOneSinkCategory() {
        Map<String, String> expected = Map.of(
                "sql_injection", "SQL_EXECUTION",
                "xss", "HTTP_RESPONSE_WRITE",
                "xxe", "XML_PARSE",
                "actuator", "ACTUATOR_ENDPOINT",
                "crlf_injection", "HTTP_HEADER_WRITE",
                "open_redirect", "HTTP_REDIRECT"
        );

        expected.forEach((hunter, category) ->
                assertThat(EvidencePackagePolicy.sinkCategories(hunter))
                        .as(hunter)
                        .contains(category));
    }
}
