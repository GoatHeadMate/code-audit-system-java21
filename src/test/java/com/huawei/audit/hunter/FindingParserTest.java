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
                .containsEntry("discovered_by", "sql_injection")
                .containsEntry("verdict", "CONFIRM")
                .containsEntry("status", "CONFIRM");
    }

    @Test
    void normalizesNeedsReviewStatusAsVerdict() {
        String response = """
                [{
                  "rule_id": "authz-tenant-bypass",
                  "status": "needs_review",
                  "severity": "medium",
                  "confidence": "medium",
                  "file_path": "src/Admin.java",
                  "start_line": 7,
                  "message": "Tenant check is incomplete"
                }]
                """;

        var findings = parser.parse(response, "authorization");

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst())
                .containsEntry("verdict", "NEEDS_REVIEW")
                .containsEntry("status", "NEEDS_REVIEW");
    }

    @Test
    void normalizesFreeFormVulnerabilityTypesBeforeAggregation() {
        String response = """
                [
                  {
                    "rule_id": "authz-csrf-disabled",
                    "vuln_type": "BROKEN ACCESS CONTROL - CSRF PROTECTION DISABLED",
                    "title": "CSRF protection is disabled"
                  },
                  {
                    "rule_id": "authz-jwt-weak-secret",
                    "vuln_type": "BROKEN ACCESS CONTROL - HARDCODED WEAK JWT SECRET ENABLES TOKEN FORGERY",
                    "title": "Weak JWT secret"
                  },
                  {
                    "rule_id": "auth-bypass-open-endpoint",
                    "vuln_type": "AUTHENTICATION_BYPASS",
                    "title": "Authentication bypass"
                  },
                  {
                    "rule_id": "pathtrav-read",
                    "vuln_type": "PATH_TRAVERSAL_OR_ARBITRARY_FILE_ACCESS",
                    "title": "Arbitrary file read"
                  },
                  {
                    "rule_id": "component-config",
                    "vuln_type": "COMPONENT_OR_CONFIGURATION_VULNERABILITY",
                    "title": "Exposed component"
                  }
                ]
                """;

        var findings = parser.parse(response, "authorization");

        assertThat(findings)
                .extracting(finding -> finding.get("vuln_type"))
                .containsExactly(
                        "CSRF",
                        "JWT_WEAKNESS",
                        "AUTH_BYPASS",
                        "PATH_TRAVERSAL",
                        "COMPONENT_VULN"
                );
        assertThat(findings.getFirst())
                .containsEntry(
                        "original_vuln_type",
                        "BROKEN ACCESS CONTROL - CSRF PROTECTION DISABLED"
                );
    }
}
