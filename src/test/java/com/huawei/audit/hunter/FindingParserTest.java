package com.huawei.audit.hunter;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class FindingParserTest {
    private final FindingParser parser = new FindingParser(new ObjectMapper());

    @Test
    void extractsFencedJsonAndNormalizesLegacyFields() {
        String response = """
                analysis complete
                ```json
                [{
                  "rule_id": "sqli-1",
                  "severity": "high",
                  "confidence": 0.91,
                  "file": "src/UserDao.java",
                  "line": "42",
                  "description": "SQL is concatenated"
                }]
                ```
                """;

        var findings = parser.parse(response, "sql_injection");

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst())
                .containsEntry("file_path", "src/UserDao.java")
                .containsEntry("start_line", 42)
                .containsEntry("message", "SQL is concatenated")
                .containsEntry("vuln_type", "SQL_INJECTION")
                .containsEntry("discovered_by", "sql_injection");
    }
}
