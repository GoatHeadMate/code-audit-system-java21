package com.huawei.audit.orchestrator;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class FindingDeduplicator {
    private static final Map<String, Integer> SEVERITY = Map.of(
            "CRITICAL", 4,
            "HIGH", 3,
            "MEDIUM", 2,
            "LOW", 1
    );

    public List<Map<String, Object>> deduplicate(List<Map<String, Object>> findings) {
        Map<String, Map<String, Object>> best = new LinkedHashMap<>();
        for (Map<String, Object> finding : findings) {
            String key = finding.getOrDefault("rule_id", "") + "|"
                    + finding.getOrDefault("file_path", "") + "|"
                    + finding.getOrDefault("start_line", 0);
            Map<String, Object> existing = best.get(key);
            if (existing == null || confidence(finding) > confidence(existing)) {
                best.put(key, finding);
            }
        }

        List<Map<String, Object>> result = new ArrayList<>(best.values());
        result.sort(Comparator
                .comparingInt(this::severity)
                .thenComparingDouble(this::confidence)
                .reversed());
        return result;
    }

    public Map<String, Object> statistics(List<Map<String, Object>> findings) {
        Map<String, Integer> bySeverity = new LinkedHashMap<>();
        Map<String, Integer> byAgent = new LinkedHashMap<>();
        Map<String, Integer> byType = new LinkedHashMap<>();
        for (Map<String, Object> finding : findings) {
            increment(bySeverity, text(finding, "severity", "UNKNOWN").toUpperCase());
            increment(byAgent, text(finding, "discovered_by", "unknown"));
            increment(byType, text(finding, "vuln_type", "UNKNOWN"));
        }
        return Map.of(
                "total", findings.size(),
                "by_severity", bySeverity,
                "by_agent", byAgent,
                "by_vuln_type", byType
        );
    }

    private void increment(Map<String, Integer> values, String key) {
        values.merge(key, 1, Integer::sum);
    }

    private int severity(Map<String, Object> finding) {
        return SEVERITY.getOrDefault(text(finding, "severity", "").toUpperCase(), 0);
    }

    private double confidence(Map<String, Object> finding) {
        Object value = finding.get("confidence");
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value != null) {
            return switch (value.toString().toUpperCase()) {
                case "HIGH" -> 0.90;
                case "MEDIUM" -> 0.70;
                case "LOW" -> 0.50;
                default -> parseConfidence(value);
            };
        }
        return 0.0;
    }

    private double parseConfidence(Object value) {
        try {
            return Double.parseDouble(value.toString());
        } catch (NumberFormatException ignored) {
            return 0.0;
        }
    }

    private String text(Map<String, Object> finding, String key, String fallback) {
        Object value = finding.get(key);
        return value == null || value.toString().isBlank() ? fallback : value.toString();
    }
}
