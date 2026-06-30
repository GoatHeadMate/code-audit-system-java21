package com.huawei.audit.memory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.AuditProperties;
import com.huawei.audit.domain.AuditJob;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Service;

@Service
public class JsonlAuditMemoryService implements AuditMemoryService {
    private static final int SCHEMA_VERSION = 1;
    private static final int MAX_RECALL_PRIORS = 8;
    private static final int MAX_RECALL_LINES = 5_000;
    private static final int MIN_RECALL_SCORE = 2;
    private static final Map<String, Set<String>> HUNTER_TYPES = Map.of(
            "code_execution", Set.of(
                    "COMMAND_INJECTION", "SCRIPT_INJECTION",
                    "EXPRESSION_INJECTION", "TEMPLATE_INJECTION",
                    "UNSAFE_CLASS_LOADING"
            ),
            "authorization", Set.of(
                    "BROKEN_ACCESS_CONTROL", "IDOR", "AUTH_BYPASS",
                    "CSRF", "JWT_WEAKNESS", "COOKIE_SECURITY"
            ),
            "sql_injection", Set.of("SQL_INJECTION"),
            "unsafe_parsing", Set.of(
                    "XXE", "DESERIALIZATION", "EXPRESSION_INJECTION",
                    "TEMPLATE_INJECTION", "UNSAFE_CLASS_LOADING"
            ),
            "ssrf", Set.of("SSRF"),
            "file_operations", Set.of("PATH_TRAVERSAL", "FILE_UPLOAD"),
            "http_output", Set.of(
                    "XSS", "CRLF_INJECTION", "OPEN_REDIRECT",
                    "CORS_MISCONFIG", "JSONP_HIJACK"
            ),
            "component_vulns", Set.of(
                    "COMPONENT_VULN", "LOG4SHELL", "ACTUATOR_EXPOSURE"
            )
    );

    private final ObjectMapper objectMapper;
    private final Path memoryFile;

    public JsonlAuditMemoryService(
            ObjectMapper objectMapper,
            AuditProperties properties
    ) {
        this.objectMapper = objectMapper;
        this.memoryFile = properties.absoluteWorkspace()
                .resolve("audit-memory")
                .resolve("findings.jsonl");
    }

    @Override
    public synchronized void rememberFindings(
            AuditJob job,
            Path sourceRoot,
            Map<String, Object> techProfile,
            List<Map<String, Object>> findings
    ) {
        if (job == null || findings == null || findings.isEmpty()) {
            return;
        }
        try {
            Files.createDirectories(memoryFile.getParent());
            StringBuilder lines = new StringBuilder();
            Instant now = Instant.now();
            List<String> dependencyKeys = dependencyKeys(techProfile);
            for (Map<String, Object> finding : findings) {
                if (!shouldRemember(finding)) {
                    continue;
                }
                Map<String, Object> event = new LinkedHashMap<>();
                event.put("schema_version", SCHEMA_VERSION);
                event.put("event_type", "finding_observed");
                event.put("recorded_at", now.toString());
                event.put("job_id", job.jobId());
                event.put("lang", job.lang());
                event.put("source_type", job.sourceType());
                event.put("git_url", job.gitUrl());
                event.put("cache_key", job.cacheKey());
                event.put("source_root", sourceRoot == null
                        ? ""
                        : sourceRoot.toAbsolutePath().normalize().toString());
                event.put("dependency_keys", dependencyKeys);
                copy(event, finding, "rule_id");
                copy(event, finding, "vuln_type");
                copy(event, finding, "title");
                copy(event, finding, "severity");
                copy(event, finding, "confidence");
                copy(event, finding, "verdict");
                copy(event, finding, "status");
                copy(event, finding, "file_path");
                copy(event, finding, "start_line");
                copy(event, finding, "http_method");
                copy(event, finding, "http_path");
                copy(event, finding, "discovered_by");
                event.put("memory_policy",
                        "historical-prior-only; revalidate from current source");
                lines.append(objectMapper.writeValueAsString(event))
                        .append(System.lineSeparator());
            }
            if (!lines.isEmpty()) {
                Files.writeString(memoryFile, lines.toString(),
                        StandardOpenOption.CREATE,
                        StandardOpenOption.APPEND);
            }
        } catch (Exception ignored) {
        }
    }

    @Override
    public List<Map<String, Object>> recallPriors(
            AuditJob job,
            String hunter,
            String teamFocus,
            List<Map<String, Object>> endpointSurface,
            List<Map<String, String>> dependencies
    ) {
        if (!Files.isRegularFile(memoryFile)) {
            return List.of();
        }
        try {
            String baseHunter = baseHunterName(hunter);
            Set<String> relevantTypes = HUNTER_TYPES.getOrDefault(baseHunter, Set.of());
            Set<String> currentDependencies = dependencyKeysFromList(dependencies);
            Set<String> endpointPaths = endpointValues(endpointSurface, "path");
            Set<String> endpointFiles = endpointValues(endpointSurface, "file_path");
            Map<String, PriorAccumulator> priors = new LinkedHashMap<>();

            for (String line : recentLines()) {
                if (line.isBlank()) {
                    continue;
                }
                JsonNode node = objectMapper.readTree(line);
                if (job != null && job.jobId().equals(text(node, "job_id"))) {
                    continue;
                }
                String type = text(node, "vuln_type");
                if (!relevantTypes.isEmpty() && !relevantTypes.contains(type)) {
                    continue;
                }
                int score = score(node, currentDependencies, endpointPaths,
                        endpointFiles, teamFocus);
                if (score < MIN_RECALL_SCORE) {
                    continue;
                }
                String key = String.join("|",
                        type,
                        text(node, "rule_id"),
                        fileName(text(node, "file_path")),
                        text(node, "http_path"));
                priors.computeIfAbsent(key, ignored ->
                        new PriorAccumulator(type, text(node, "rule_id")))
                        .add(node, score);
            }

            return priors.values().stream()
                    .sorted(Comparator.comparingInt(PriorAccumulator::score).reversed())
                    .limit(MAX_RECALL_PRIORS)
                    .map(PriorAccumulator::toMap)
                    .toList();
        } catch (Exception ignored) {
            return List.of();
        }
    }

    private boolean shouldRemember(Map<String, Object> finding) {
        String type = text(finding, "vuln_type");
        if (type.isBlank() || "ATTACK_CHAIN".equals(type)) {
            return false;
        }
        String verdict = text(finding, "verdict", "status");
        return verdict.isBlank()
                || "CONFIRM".equals(verdict)
                || "NEEDS_REVIEW".equals(verdict);
    }

    private int score(
            JsonNode node,
            Set<String> dependencies,
            Set<String> endpointPaths,
            Set<String> endpointFiles,
            String teamFocus
    ) {
        int score = 0;
        if (overlaps(dependencies, dependencyKeys(node.path("dependency_keys")))) {
            score += 2;
        }
        String httpPath = text(node, "http_path").toLowerCase(Locale.ROOT);
        if (!httpPath.isBlank() && endpointPaths.contains(httpPath)) {
            score += 3;
        }
        String file = text(node, "file_path").toLowerCase(Locale.ROOT)
                .replace('\\', '/');
        if (!file.isBlank() && endpointFiles.contains(file)) {
            score += 3;
        }
        String focus = normalize(teamFocus);
        if (!focus.isBlank() && normalize(text(node, "vuln_type")).contains(focus)) {
            score += 1;
        }
        return score;
    }

    private List<String> recentLines() throws Exception {
        List<String> lines = Files.readAllLines(memoryFile);
        if (lines.size() <= MAX_RECALL_LINES) {
            return lines;
        }
        return lines.subList(lines.size() - MAX_RECALL_LINES, lines.size());
    }

    private List<String> dependencyKeys(Map<String, Object> techProfile) {
        Object raw = techProfile == null ? null : techProfile.get("dependencies");
        if (!(raw instanceof List<?> items)) {
            return List.of();
        }
        Set<String> keys = new LinkedHashSet<>();
        for (Object item : items) {
            if (item instanceof Map<?, ?> map) {
                keys.add(dependencyKey(map.get("group_id"), map.get("artifact_id")));
            }
        }
        return keys.stream().filter(key -> !key.isBlank()).toList();
    }

    private Set<String> dependencyKeysFromList(List<Map<String, String>> dependencies) {
        Set<String> keys = new LinkedHashSet<>();
        if (dependencies == null) {
            return keys;
        }
        for (Map<String, String> dependency : dependencies) {
            keys.add(dependencyKey(
                    dependency.get("group_id"),
                    dependency.get("artifact_id")
            ));
        }
        keys.remove("");
        return keys;
    }

    private Set<String> dependencyKeys(JsonNode node) {
        Set<String> keys = new LinkedHashSet<>();
        if (node.isArray()) {
            node.forEach(item -> {
                if (!item.asText("").isBlank()) {
                    keys.add(item.asText().toLowerCase(Locale.ROOT));
                }
            });
        }
        return keys;
    }

    private String dependencyKey(Object groupId, Object artifactId) {
        String group = groupId == null ? "" : groupId.toString().strip();
        String artifact = artifactId == null ? "" : artifactId.toString().strip();
        if (group.isBlank() && artifact.isBlank()) {
            return "";
        }
        return (group + ":" + artifact).toLowerCase(Locale.ROOT);
    }

    private Set<String> endpointValues(
            List<Map<String, Object>> endpointSurface,
            String key
    ) {
        Set<String> values = new LinkedHashSet<>();
        if (endpointSurface == null) {
            return values;
        }
        for (Map<String, Object> endpoint : endpointSurface) {
            Object value = endpoint.get(key);
            if (value != null && !value.toString().isBlank()) {
                values.add(value.toString().replace('\\', '/')
                        .toLowerCase(Locale.ROOT));
            }
        }
        return values;
    }

    private boolean overlaps(Set<String> left, Set<String> right) {
        if (left.isEmpty() || right.isEmpty()) {
            return false;
        }
        for (String item : left) {
            if (right.contains(item)) {
                return true;
            }
        }
        return false;
    }

    private String baseHunterName(String hunter) {
        String value = hunter == null ? "" : hunter;
        int batchIdx = value.indexOf("_batch_");
        String withoutBatch = batchIdx >= 0 ? value.substring(0, batchIdx) : value;
        int teamIdx = withoutBatch.indexOf("_team_");
        return teamIdx >= 0 ? withoutBatch.substring(0, teamIdx) : withoutBatch;
    }

    private String fileName(String filePath) {
        String normalized = filePath == null ? "" : filePath.replace('\\', '/');
        int slash = normalized.lastIndexOf('/');
        return slash >= 0 ? normalized.substring(slash + 1) : normalized;
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

    private String text(Map<String, Object> map, String... keys) {
        for (String key : keys) {
            Object value = map.get(key);
            if (value != null && !value.toString().isBlank()) {
                return normalizeValue(key, value.toString());
            }
        }
        return "";
    }

    private String text(JsonNode node, String key) {
        JsonNode value = node.path(key);
        return value.isMissingNode() || value.isNull()
                ? ""
                : normalizeValue(key, value.asText(""));
    }

    private String normalizeValue(String key, String value) {
        if ("vuln_type".equals(key) || "verdict".equals(key) || "status".equals(key)) {
            return value.strip().toUpperCase(Locale.ROOT);
        }
        return value.strip();
    }

    private String normalize(String value) {
        return value == null
                ? ""
                : value.toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]+", "_");
    }

    private static final class PriorAccumulator {
        private final String vulnType;
        private final String ruleId;
        private final List<Map<String, Object>> examples = new ArrayList<>();
        private int score;

        PriorAccumulator(String vulnType, String ruleId) {
            this.vulnType = vulnType;
            this.ruleId = ruleId;
        }

        void add(JsonNode node, int matchScore) {
            score += matchScore;
            examples.add(Map.of(
                    "job_id", textStatic(node, "job_id"),
                    "file_path", textStatic(node, "file_path"),
                    "start_line", textStatic(node, "start_line"),
                    "http_path", textStatic(node, "http_path"),
                    "title", textStatic(node, "title"),
                    "recorded_at", textStatic(node, "recorded_at")
            ));
            examples.sort(Comparator.comparing(example ->
                    example.getOrDefault("recorded_at", "").toString()));
        }

        int score() {
            return score + examples.size();
        }

        Map<String, Object> toMap() {
            Map<String, Object> prior = new LinkedHashMap<>();
            prior.put("kind", "HISTORICAL_FINDING_PRIOR");
            prior.put("vuln_type", vulnType);
            prior.put("rule_id", ruleId);
            prior.put("support_count", examples.size());
            prior.put("examples", examples.stream()
                    .skip(Math.max(0, examples.size() - 3))
                    .toList());
            prior.put("policy",
                    "Prior only: use as attention guidance; re-validate from current source before reporting.");
            return prior;
        }

        private static String textStatic(JsonNode node, String key) {
            JsonNode value = node.path(key);
            return value.isMissingNode() || value.isNull() ? "" : value.asText("");
        }
    }
}
