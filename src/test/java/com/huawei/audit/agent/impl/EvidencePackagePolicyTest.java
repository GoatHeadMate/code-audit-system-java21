package com.huawei.audit.agent.impl;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class EvidencePackagePolicyTest {
    @Test
    void mapsEveryConfiguredHunterToAtLeastOneSinkCategory() {
        Map<String, String> expected = Map.of(
                "sql_injection", "SQL_EXECUTION",
                "http_output", "HTTP_RESPONSE_WRITE",
                "unsafe_parsing", "XML_PARSE",
                "component_vulns", "ACTUATOR_ENDPOINT",
                "code_execution", "COMMAND_EXECUTION",
                "file_operations", "FILE_WRITE"
        );

        expected.forEach((hunter, category) ->
                assertThat(EvidencePackagePolicy.sinkCategories(hunter))
                        .as(hunter)
                        .contains(category));
    }
}
