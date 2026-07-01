package com.huawei.audit.agent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class FindingConsolidator {
    private static final Map<String, Integer> SEVERITY_RANK = Map.of(
            "CRITICAL", 5,
            "HIGH", 4,
            "MEDIUM", 3,
            "LOW", 2,
            "INFO", 1
    );

    public List<Map<String, Object>> consolidate(List<Map<String, Object>> findings) {
        if (findings == null || findings.isEmpty()) {
            return List.of();
        }
        Map<String, Accumulator> grouped = new LinkedHashMap<>();
        for (Map<String, Object> finding : findings) {
            if (finding == null || finding.isEmpty()) {
                continue;
            }
            grouped.computeIfAbsent(key(finding), ignored -> new Accumulator())
                    .add(finding);
        }
        return grouped.values().stream()
                .map(Accumulator::toMap)
                .toList();
    }

    private String key(Map<String, Object> finding) {
        String type = text(finding, "vuln_type", "vulnerability_type");
        if ("ATTACK_CHAIN".equals(type)) {
            return "ATTACK_CHAIN|" + chainKind(finding);
        }
        String httpPath = normalizedPath(text(finding, "http_path"));
        String filePath = normalizedFile(text(finding, "file_path"));
        if (!httpPath.isBlank()) {
            return String.join("|", type, httpPath, filePath);
        }
        String line = text(finding, "start_line", "line");
        String rule = normalize(text(finding, "rule_id"));
        if (!filePath.isBlank()) {
            return String.join("|", type, filePath, line.isBlank() ? rule : line);
        }
        return String.join("|", type, rule, normalize(text(finding, "title", "message")));
    }

    private String chainKind(Map<String, Object> finding) {
        String haystack = normalize(String.join(" ",
                text(finding, "rule_id"),
                text(finding, "title"),
                text(finding, "message"),
                text(finding, "evidence"),
                text(finding, "http_path")
        ));
        boolean unauth = containsAny(haystack, "unauth", "noauth", "permitall");
        boolean ssrf = haystack.contains("ssrf");
        boolean rce = containsAny(haystack, "rce", "command", "cmdinj", "spel", "qlexpress",
                "groovy", "script", "ssti", "classload");
        boolean deserialization = containsAny(haystack, "deser", "shiro", "fastjson", "xstream",
                "jackson");
        boolean xxe = haystack.contains("xxe");
        boolean sql = haystack.contains("sql");
        if (unauth && rce) {
            return "unauth-rce";
        }
        if (ssrf && rce) {
            return "ssrf-rce";
        }
        if (ssrf && deserialization) {
            return "ssrf-deserialization";
        }
        if (ssrf && xxe) {
            return "ssrf-xxe";
        }
        if (unauth && ssrf) {
            return "unauth-ssrf";
        }
        if (unauth && deserialization) {
            return "unauth-deserialization";
        }
        if (sql && rce) {
            return "sql-rce";
        }
        return normalize(text(finding, "rule_id", "title", "message"));
    }

    private boolean containsAny(String value, String... needles) {
        for (String needle : needles) {
            if (value.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private String normalizedPath(String value) {
        String path = value.replace('\\', '/').strip().toLowerCase(Locale.ROOT);
        if (path.contains(",")) {
            return path;
        }
        return path.replaceAll("/+", "/");
    }

    private String normalizedFile(String value) {
        return value.replace('\\', '/').strip().toLowerCase(Locale.ROOT);
    }

    private String normalize(String value) {
        return value == null
                ? ""
                : value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-")
                .replaceAll("^-|-$", "");
    }

    private String text(Map<String, Object> finding, String... keys) {
        for (String key : keys) {
            Object value = finding.get(key);
            if (value != null && !value.toString().isBlank()) {
                return value.toString().strip().toUpperCase(Locale.ROOT);
            }
        }
        return "";
    }

    private final class Accumulator {
        private Map<String, Object> primary = Map.of();
        private final List<Map<String, Object>> variants = new ArrayList<>();
        private final Set<String> ruleIds = new LinkedHashSet<>();
        private final Set<String> sources = new LinkedHashSet<>();
        private final Set<String> hunters = new LinkedHashSet<>();

        void add(Map<String, Object> finding) {
            variants.add(finding);
            addIfPresent(ruleIds, finding, "rule_id");
            addIfPresent(sources, finding, "discovery_source");
            addIfPresent(hunters, finding, "discovered_by");
            if (primary.isEmpty() || better(finding, primary)) {
                primary = finding;
            }
        }

        Map<String, Object> toMap() {
            Map<String, Object> output = new LinkedHashMap<>(primary);
            if (variants.size() <= 1) {
                return output;
            }
            output.put("merged_count", variants.size());
            output.put("merged_rule_ids", List.copyOf(ruleIds));
            output.put("merged_discovery_sources", List.copyOf(sources));
            output.put("merged_hunters", List.copyOf(hunters));
            output.put("merged_from", variants.stream()
                    .map(FindingConsolidator.this::variantSummary)
                    .toList());
            String message = String.valueOf(output.getOrDefault("message", ""));
            output.put("message", message.isBlank()
                    ? "Merged " + variants.size() + " duplicate reports for the same vulnerability surface."
                    : message + " Merged " + variants.size()
                            + " duplicate reports for the same vulnerability surface.");
            return output;
        }

        private boolean better(Map<String, Object> left, Map<String, Object> right) {
            int severity = Integer.compare(rank(left, "severity"), rank(right, "severity"));
            if (severity != 0) {
                return severity > 0;
            }
            int verdict = Integer.compare(rank(left, "verdict", "status"), rank(right, "verdict", "status"));
            if (verdict != 0) {
                return verdict > 0;
            }
            return text(left, "evidence", "message").length()
                    > text(right, "evidence", "message").length();
        }

        private int rank(Map<String, Object> finding, String... keys) {
            String value = text(finding, keys);
            if (SEVERITY_RANK.containsKey(value)) {
                return SEVERITY_RANK.get(value);
            }
            return switch (value) {
                case "CONFIRM" -> 5;
                case "NEEDS_REVIEW" -> 3;
                case "DOWNGRADE" -> 2;
                case "SUPPRESS" -> 1;
                default -> 0;
            };
        }

        private void addIfPresent(
                Set<String> values,
                Map<String, Object> finding,
                String key
        ) {
            Object value = finding.get(key);
            if (value != null && !value.toString().isBlank()) {
                values.add(value.toString());
            }
        }
    }

    private Map<String, Object> variantSummary(Map<String, Object> finding) {
        Map<String, Object> summary = new LinkedHashMap<>();
        copy(summary, finding, "rule_id");
        copy(summary, finding, "title");
        copy(summary, finding, "vuln_type");
        copy(summary, finding, "severity");
        copy(summary, finding, "confidence");
        copy(summary, finding, "http_path");
        copy(summary, finding, "file_path");
        copy(summary, finding, "start_line");
        copy(summary, finding, "discovery_source");
        copy(summary, finding, "discovered_by");
        return summary;
    }

    private void copy(
            Map<String, Object> target,
            Map<String, Object> source,
            String key
    ) {
        Object value = source.get(key);
        if (value != null && !value.toString().isBlank()) {
            target.put(key, value);
        }
    }
}
