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
import java.util.Optional;
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
    private final Path feedbackFile;
    private final Path ruleCandidatesFile;
    private final Path ruleDecisionsFile;
    private final Path approvedRulesFile;
    private final Path agentRunsFile;

    public JsonlAuditMemoryService(
            ObjectMapper objectMapper,
            AuditProperties properties
    ) {
        this.objectMapper = objectMapper;
        this.memoryFile = properties.absoluteWorkspace()
                .resolve("audit-memory")
                .resolve("findings.jsonl");
        this.feedbackFile = properties.absoluteWorkspace()
                .resolve("audit-memory")
                .resolve("feedback.jsonl");
        this.ruleCandidatesFile = properties.absoluteWorkspace()
                .resolve("audit-memory")
                .resolve("rule-candidates.jsonl");
        this.ruleDecisionsFile = properties.absoluteWorkspace()
                .resolve("audit-memory")
                .resolve("rule-decisions.jsonl");
        this.approvedRulesFile = properties.absoluteWorkspace()
                .resolve("audit-memory")
                .resolve("approved-rules.jsonl");
        this.agentRunsFile = properties.absoluteWorkspace()
                .resolve("audit-memory")
                .resolve("agent-runs.jsonl");
    }

    @Override
    public synchronized void rememberFeedback(
            AuditJob job,
            int findingIndex,
            Map<String, Object> finding,
            String verdict,
            String rationale,
            String reviewer
    ) {
        rememberFeedback(job, findingIndex, finding, verdict, rationale, reviewer,
                "", "", "");
    }

    @Override
    public synchronized void rememberFeedback(
            AuditJob job,
            int findingIndex,
            Map<String, Object> finding,
            String verdict,
            String rationale,
            String reviewer,
            String pocStatus,
            String learningNote,
            String targetSeverity
    ) {
        if (job == null || finding == null || finding.isEmpty()) {
            return;
        }
        String normalizedVerdict = normalizeFeedbackVerdict(verdict);
        if (normalizedVerdict.isBlank()) {
            return;
        }
        try {
            Files.createDirectories(feedbackFile.getParent());
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("schema_version", SCHEMA_VERSION);
            event.put("event_type", "finding_feedback");
            event.put("recorded_at", Instant.now().toString());
            event.put("job_id", job.jobId());
            event.put("finding_index", findingIndex);
            event.put("feedback_verdict", normalizedVerdict);
            event.put("learning_signal", learningSignal(normalizedVerdict));
            event.put("poc_status", normalizePocStatus(pocStatus));
            event.put("feedback_rationale", safeText(rationale));
            event.put("learning_note", safeText(learningNote));
            event.put("target_severity", normalizeSeverity(targetSeverity));
            event.put("reviewer", safeText(reviewer));
            event.put("lang", job.lang());
            event.put("source_type", job.sourceType());
            event.put("git_url", job.gitUrl());
            event.put("cache_key", job.cacheKey());
            event.put("dependency_keys", dependencyKeys(job.techProfile()));
            copy(event, finding, "rule_id");
            copy(event, finding, "vuln_type");
            copy(event, finding, "title");
            copy(event, finding, "severity");
            copy(event, finding, "confidence");
            copy(event, finding, "file_path");
            copy(event, finding, "start_line");
            copy(event, finding, "http_method");
            copy(event, finding, "http_path");
            copy(event, finding, "discovered_by");
            event.put("memory_policy",
                    "feedback-prior-only; revalidate from current source");
            Files.writeString(feedbackFile,
                    objectMapper.writeValueAsString(event) + System.lineSeparator(),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);
            refreshRuleCandidates();
        } catch (Exception ignored) {
        }
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
                refreshRuleCandidates();
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
        if (!Files.isRegularFile(memoryFile)
                && !Files.isRegularFile(feedbackFile)
                && !Files.isRegularFile(approvedRulesFile)) {
            return List.of();
        }
        try {
            String baseHunter = baseHunterName(hunter);
            Set<String> relevantTypes = HUNTER_TYPES.getOrDefault(baseHunter, Set.of());
            Set<String> currentDependencies = dependencyKeysFromList(dependencies);
            Set<String> endpointPaths = endpointValues(endpointSurface, "path");
            Set<String> endpointFiles = endpointValues(endpointSurface, "file_path");
            Map<String, PriorAccumulator> priors = new LinkedHashMap<>();

            for (String line : recentLines(memoryFile)) {
                collectPrior(job, relevantTypes, currentDependencies,
                        endpointPaths, endpointFiles, teamFocus, priors, line);
            }
            for (String line : recentLines(feedbackFile)) {
                collectPrior(job, relevantTypes, currentDependencies,
                        endpointPaths, endpointFiles, teamFocus, priors, line);
            }
            for (String line : recentLines(approvedRulesFile)) {
                collectPrior(job, relevantTypes, currentDependencies,
                        endpointPaths, endpointFiles, teamFocus, priors, line);
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

    @Override
    public synchronized List<Map<String, Object>> listRuleCandidates() {
        try {
            refreshRuleCandidates();
            return readJsonlMaps(ruleCandidatesFile);
        } catch (Exception ignored) {
            return List.of();
        }
    }

    @Override
    public synchronized Optional<Map<String, Object>> decideRuleCandidate(
            String candidateId,
            String decision,
            String rationale,
            String reviewer
    ) {
        String normalizedDecision = normalizeRuleDecision(decision);
        String normalizedCandidateId = safeText(candidateId);
        if (normalizedCandidateId.isBlank() || normalizedDecision.isBlank()) {
            return Optional.empty();
        }
        try {
            refreshRuleCandidates();
            Optional<Map<String, Object>> existing = readJsonlMaps(ruleCandidatesFile)
                    .stream()
                    .filter(candidate -> normalizedCandidateId.equals(
                            candidate.getOrDefault("candidate_id", "").toString()))
                    .findFirst();
            if (existing.isEmpty()) {
                return Optional.empty();
            }

            Files.createDirectories(ruleDecisionsFile.getParent());
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("schema_version", SCHEMA_VERSION);
            event.put("event_type", "rule_candidate_decision");
            event.put("recorded_at", Instant.now().toString());
            event.put("candidate_id", normalizedCandidateId);
            event.put("decision", normalizedDecision);
            event.put("rationale", safeText(rationale));
            event.put("reviewer", safeText(reviewer));
            event.put("memory_policy",
                    "human-gated-rule-decision; approved rules remain priors only");
            Files.writeString(ruleDecisionsFile,
                    objectMapper.writeValueAsString(event) + System.lineSeparator(),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);
            refreshRuleCandidates();
            return readJsonlMaps(ruleCandidatesFile)
                    .stream()
                    .filter(candidate -> normalizedCandidateId.equals(
                            candidate.getOrDefault("candidate_id", "").toString()))
                    .findFirst();
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }

    @Override
    public synchronized void rememberAgentRun(
            AuditJob job,
            Map<String, Object> agentRun
    ) {
        if (job == null || agentRun == null || agentRun.isEmpty()) {
            return;
        }
        try {
            Files.createDirectories(agentRunsFile.getParent());
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("schema_version", SCHEMA_VERSION);
            event.put("event_type", "agent_run");
            event.put("recorded_at", Instant.now().toString());
            event.put("job_id", job.jobId());
            event.put("lang", job.lang());
            event.put("source_type", job.sourceType());
            event.put("git_url", job.gitUrl());
            event.put("cache_key", job.cacheKey());
            event.putAll(agentRun);
            event.put("memory_policy",
                    "agent-behavior-telemetry; scheduling-prior-only");
            Files.writeString(agentRunsFile,
                    objectMapper.writeValueAsString(event) + System.lineSeparator(),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);
        } catch (Exception ignored) {
        }
    }

    @Override
    public List<Map<String, Object>> recallApprovedRules(
            AuditJob job,
            String hunter,
            String teamFocus,
            List<Map<String, Object>> endpointSurface,
            List<Map<String, String>> dependencies
    ) {
        if (!Files.isRegularFile(approvedRulesFile)) {
            return List.of();
        }
        try {
            String baseHunter = baseHunterName(hunter);
            Set<String> relevantTypes = HUNTER_TYPES.getOrDefault(baseHunter, Set.of());
            Set<String> currentDependencies = dependencyKeysFromList(dependencies);
            Set<String> endpointPaths = endpointValues(endpointSurface, "path");
            Set<String> endpointFiles = endpointValues(endpointSurface, "file_path");
            List<Map<String, Object>> rules = new ArrayList<>();
            for (String line : recentLines(approvedRulesFile)) {
                if (line.isBlank()) {
                    continue;
                }
                JsonNode node = objectMapper.readTree(line);
                String type = text(node, "vuln_type");
                if (!relevantTypes.isEmpty() && !relevantTypes.contains(type)) {
                    continue;
                }
                int score = score(node, currentDependencies, endpointPaths,
                        endpointFiles, teamFocus);
                if (score < MIN_RECALL_SCORE) {
                    continue;
                }
                Map<String, Object> rule = new LinkedHashMap<>();
                rule.put("rule_id", text(node, "rule_id"));
                rule.put("vuln_type", type);
                rule.put("file_pattern", text(node, "file_pattern"));
                rule.put("http_path", text(node, "http_path"));
                rule.put("confidence_score", node.path("confidence_score").asDouble(0));
                rule.put("support_count", node.path("support_count").asInt(0));
                rule.put("match_score", score);
                rule.put("suggested_agent_guidance",
                        text(node, "suggested_agent_guidance"));
                rule.put("decision_rationale", text(node, "decision_rationale"));
                rule.put("decision_reviewer", text(node, "decision_reviewer"));
                rule.put("decided_at", text(node, "decided_at"));
                rule.put("policy",
                        "Approved rule guidance only; re-validate current source before reporting, suppressing or lowering severity.");
                rules.add(rule);
            }
            return rules.stream()
                    .sorted(Comparator
                            .comparingInt((Map<String, Object> rule) ->
                                    ((Number) rule.getOrDefault("match_score", 0)).intValue())
                            .reversed()
                            .thenComparing(rule -> rule.getOrDefault("rule_id", "").toString()))
                    .limit(MAX_RECALL_PRIORS)
                    .toList();
        } catch (Exception ignored) {
            return List.of();
        }
    }

    private void collectPrior(
            AuditJob job,
            Set<String> relevantTypes,
            Set<String> currentDependencies,
            Set<String> endpointPaths,
            Set<String> endpointFiles,
            String teamFocus,
            Map<String, PriorAccumulator> priors,
            String line
    ) throws Exception {
        if (line.isBlank()) {
            return;
        }
        JsonNode node = objectMapper.readTree(line);
        if (job != null && job.jobId().equals(text(node, "job_id"))) {
            return;
        }
        String type = text(node, "vuln_type");
        if (!relevantTypes.isEmpty() && !relevantTypes.contains(type)) {
            return;
        }
        int score = score(node, currentDependencies, endpointPaths,
                endpointFiles, teamFocus);
        if (score < MIN_RECALL_SCORE) {
            return;
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

    private List<String> recentLines(Path file) throws Exception {
        if (!Files.isRegularFile(file)) {
            return List.of();
        }
        List<String> lines = Files.readAllLines(file);
        if (lines.size() <= MAX_RECALL_LINES) {
            return lines;
        }
        return lines.subList(lines.size() - MAX_RECALL_LINES, lines.size());
    }

    private void refreshRuleCandidates() throws Exception {
        Map<String, RuleCandidateAccumulator> candidates = new LinkedHashMap<>();
        for (String line : recentLines(memoryFile)) {
            collectRuleCandidate(candidates, line);
        }
        for (String line : recentLines(feedbackFile)) {
            collectRuleCandidate(candidates, line);
        }
        Map<String, JsonNode> decisions = latestRuleDecisions();
        List<Map<String, Object>> output = candidates.values().stream()
                .filter(RuleCandidateAccumulator::shouldEmit)
                .sorted(Comparator
                        .comparingDouble(RuleCandidateAccumulator::confidenceScore)
                        .reversed()
                        .thenComparing(RuleCandidateAccumulator::candidateId))
                .map(RuleCandidateAccumulator::toMap)
                .map(candidate -> applyRuleDecision(candidate, decisions))
                .toList();
        Files.createDirectories(ruleCandidatesFile.getParent());
        StringBuilder lines = new StringBuilder();
        for (Map<String, Object> candidate : output) {
            lines.append(objectMapper.writeValueAsString(candidate))
                    .append(System.lineSeparator());
        }
        Files.writeString(ruleCandidatesFile, lines.toString(),
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);
        writeApprovedRules(output);
    }

    private Map<String, JsonNode> latestRuleDecisions() throws Exception {
        Map<String, JsonNode> decisions = new LinkedHashMap<>();
        for (String line : recentLines(ruleDecisionsFile)) {
            if (line.isBlank()) {
                continue;
            }
            JsonNode node = objectMapper.readTree(line);
            String candidateId = text(node, "candidate_id");
            String decision = text(node, "decision");
            if (!candidateId.isBlank() && !decision.isBlank()) {
                decisions.put(candidateId, node);
            }
        }
        return decisions;
    }

    private Map<String, Object> applyRuleDecision(
            Map<String, Object> candidate,
            Map<String, JsonNode> decisions
    ) {
        String candidateId = candidate.getOrDefault("candidate_id", "").toString();
        JsonNode decision = decisions.get(candidateId);
        if (decision == null) {
            return candidate;
        }
        Map<String, Object> updated = new LinkedHashMap<>(candidate);
        String status = text(decision, "decision");
        updated.put("status", status);
        updated.put("decision_rationale", text(decision, "rationale"));
        updated.put("decision_reviewer", text(decision, "reviewer"));
        updated.put("decided_at", text(decision, "recorded_at"));
        return updated;
    }

    private void writeApprovedRules(List<Map<String, Object>> candidates) throws Exception {
        Files.createDirectories(approvedRulesFile.getParent());
        StringBuilder lines = new StringBuilder();
        for (Map<String, Object> candidate : candidates) {
            if (!"APPROVED".equals(candidate.getOrDefault("status", "").toString())) {
                continue;
            }
            Map<String, Object> rule = new LinkedHashMap<>(candidate);
            rule.put("event_type", "approved_rule");
            rule.put("recorded_at", Instant.now().toString());
            rule.put("feedback_verdict", "CONFIRM");
            rule.put("file_path", candidate.getOrDefault("file_pattern", ""));
            rule.put("memory_policy",
                    "approved-rule-prior-only; revalidate from current source");
            lines.append(objectMapper.writeValueAsString(rule))
                    .append(System.lineSeparator());
        }
        Files.writeString(approvedRulesFile, lines.toString(),
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);
    }

    private void collectRuleCandidate(
            Map<String, RuleCandidateAccumulator> candidates,
            String line
    ) throws Exception {
        if (line.isBlank()) {
            return;
        }
        JsonNode node = objectMapper.readTree(line);
        String type = text(node, "vuln_type");
        String ruleId = text(node, "rule_id");
        if (type.isBlank() || ruleId.isBlank() || "ATTACK_CHAIN".equals(type)) {
            return;
        }
        String key = String.join("|",
                type,
                ruleId,
                fileName(text(node, "file_path")),
                text(node, "http_path"));
        candidates.computeIfAbsent(key, ignored ->
                new RuleCandidateAccumulator(type, ruleId,
                        fileName(text(node, "file_path")),
                        text(node, "http_path")))
                .add(node);
    }

    private String normalizeFeedbackVerdict(String verdict) {
        String normalized = normalize(verdict);
        return switch (normalized) {
            case "CONFIRM", "CONFIRMED", "TRUE_POSITIVE" -> "CONFIRM";
            case "FALSE_POSITIVE", "SUPPRESS", "SUPPRESSED" -> "FALSE_POSITIVE";
            case "NEEDS_REVIEW", "REVIEW" -> "NEEDS_REVIEW";
            case "DUPLICATE", "DUP" -> "DUPLICATE";
            case "RISK_DOWNGRADE", "DOWNGRADE", "LOWER_RISK" -> "RISK_DOWNGRADE";
            case "MISSED_FINDING", "MISSED", "FALSE_NEGATIVE" -> "MISSED_FINDING";
            case "POC_SUCCESS", "POC_PASSED", "EXPLOIT_SUCCESS" -> "POC_SUCCESS";
            case "POC_FAILURE", "POC_FAILED", "EXPLOIT_FAILED" -> "POC_FAILURE";
            default -> "";
        };
    }

    private String learningSignal(String verdict) {
        return switch (verdict) {
            case "CONFIRM", "POC_SUCCESS" -> "TRUE_POSITIVE";
            case "FALSE_POSITIVE", "POC_FAILURE" -> "NEGATIVE_VALIDATION";
            case "RISK_DOWNGRADE" -> "RISK_ADJUSTMENT";
            case "DUPLICATE" -> "DUPLICATE";
            case "MISSED_FINDING" -> "FALSE_NEGATIVE";
            case "NEEDS_REVIEW" -> "REVIEW";
            default -> "UNKNOWN";
        };
    }

    private String normalizePocStatus(String pocStatus) {
        String normalized = normalize(pocStatus);
        return switch (normalized) {
            case "SUCCESS", "PASSED", "EXPLOIT_SUCCESS", "POC_SUCCESS" -> "SUCCESS";
            case "FAILURE", "FAILED", "EXPLOIT_FAILED", "POC_FAILURE" -> "FAILURE";
            case "NOT_RUN", "UNTESTED", "NONE" -> "NOT_RUN";
            default -> "";
        };
    }

    private String normalizeSeverity(String severity) {
        String normalized = normalize(severity);
        return switch (normalized) {
            case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO" -> normalized;
            default -> "";
        };
    }

    private String normalizeRuleDecision(String decision) {
        String normalized = normalize(decision);
        return switch (normalized) {
            case "APPROVE", "APPROVED", "ACCEPT", "ACCEPTED" -> "APPROVED";
            case "REJECT", "REJECTED", "DENY", "DENIED" -> "REJECTED";
            case "DISCARD", "DISCARDED", "DISMISS", "DISMISSED" -> "DISCARDED";
            default -> "";
        };
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> readJsonlMaps(Path file) throws Exception {
        if (!Files.isRegularFile(file)) {
            return List.of();
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        for (String line : Files.readAllLines(file)) {
            if (line.isBlank()) {
                continue;
            }
            try {
                rows.add((Map<String, Object>) objectMapper.readValue(
                        line, LinkedHashMap.class));
            } catch (Exception ignored) {
            }
        }
        return rows;
    }

    private String safeText(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.replace("\r", " ")
                .replace("\n", " ")
                .strip();
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
        private int falsePositiveFeedback;
        private int confirmFeedback;
        private int reviewFeedback;
        private int duplicateFeedback;
        private int riskDowngradeFeedback;
        private int missedFindingFeedback;
        private int pocSuccessFeedback;
        private int pocFailureFeedback;
        private int approvedRuleSupport;

        PriorAccumulator(String vulnType, String ruleId) {
            this.vulnType = vulnType;
            this.ruleId = ruleId;
        }

        void add(JsonNode node, int matchScore) {
            score += matchScore;
            String eventType = textStatic(node, "event_type");
            if ("approved_rule".equals(eventType)) {
                approvedRuleSupport++;
                score += 4;
            }
            String feedback = textStatic(node, "feedback_verdict");
            if ("FALSE_POSITIVE".equals(feedback)) {
                falsePositiveFeedback++;
            } else if ("CONFIRM".equals(feedback)) {
                confirmFeedback++;
            } else if ("NEEDS_REVIEW".equals(feedback)) {
                reviewFeedback++;
            } else if ("DUPLICATE".equals(feedback)) {
                duplicateFeedback++;
            } else if ("RISK_DOWNGRADE".equals(feedback)) {
                riskDowngradeFeedback++;
            } else if ("MISSED_FINDING".equals(feedback)) {
                missedFindingFeedback++;
            } else if ("POC_SUCCESS".equals(feedback)) {
                pocSuccessFeedback++;
                confirmFeedback++;
                score += 3;
            } else if ("POC_FAILURE".equals(feedback)) {
                pocFailureFeedback++;
                falsePositiveFeedback++;
                score += 2;
            }
            Map<String, Object> example = new LinkedHashMap<>();
            example.put("job_id", textStatic(node, "job_id"));
            example.put("file_path", textStatic(node, "file_path"));
            example.put("start_line", textStatic(node, "start_line"));
            example.put("http_path", textStatic(node, "http_path"));
            example.put("title", textStatic(node, "title"));
            example.put("feedback_verdict", feedback);
            example.put("learning_signal", textStatic(node, "learning_signal"));
            example.put("poc_status", textStatic(node, "poc_status"));
            example.put("target_severity", textStatic(node, "target_severity"));
            example.put("feedback_rationale", textStatic(node, "feedback_rationale"));
            example.put("learning_note", textStatic(node, "learning_note"));
            example.put("recorded_at", textStatic(node, "recorded_at"));
            examples.add(example);
            examples.sort(Comparator.comparing(row ->
                    row.getOrDefault("recorded_at", "").toString()));
        }

        int score() {
            return score + examples.size();
        }

        Map<String, Object> toMap() {
            Map<String, Object> prior = new LinkedHashMap<>();
            prior.put("kind", kind());
            prior.put("vuln_type", vulnType);
            prior.put("rule_id", ruleId);
            prior.put("support_count", examples.size());
            prior.put("feedback_summary", Map.of(
                    "false_positive", falsePositiveFeedback,
                    "confirm", confirmFeedback,
                    "needs_review", reviewFeedback,
                    "duplicate", duplicateFeedback,
                    "risk_downgrade", riskDowngradeFeedback,
                    "missed_finding", missedFindingFeedback,
                    "poc_success", pocSuccessFeedback,
                    "poc_failure", pocFailureFeedback,
                    "approved_rule", approvedRuleSupport
            ));
            prior.put("examples", examples.stream()
                    .skip(Math.max(0, examples.size() - 3))
                    .toList());
            prior.put("policy", policy());
            return prior;
        }

        private String kind() {
            if (approvedRuleSupport > 0) {
                return "APPROVED_RULE_PRIOR";
            }
            if (pocSuccessFeedback > 0 && falsePositiveFeedback == 0) {
                return "HISTORICAL_POC_SUCCESS_PRIOR";
            }
            if (pocFailureFeedback > 0 && confirmFeedback == 0) {
                return "HISTORICAL_NEGATIVE_VALIDATION_PRIOR";
            }
            if (falsePositiveFeedback > 0 && confirmFeedback == 0) {
                return "HISTORICAL_FALSE_POSITIVE_PRIOR";
            }
            if (confirmFeedback > 0 && falsePositiveFeedback == 0) {
                return "HISTORICAL_CONFIRMED_PRIOR";
            }
            if (riskDowngradeFeedback > 0) {
                return "HISTORICAL_RISK_ADJUSTMENT_PRIOR";
            }
            if (missedFindingFeedback > 0) {
                return "HISTORICAL_MISSED_FINDING_PRIOR";
            }
            if (duplicateFeedback > 0) {
                return "HISTORICAL_DUPLICATE_PRIOR";
            }
            if (falsePositiveFeedback > 0 || confirmFeedback > 0 || reviewFeedback > 0) {
                return "HISTORICAL_FEEDBACK_PRIOR";
            }
            return "HISTORICAL_FINDING_PRIOR";
        }

        private String policy() {
            if (approvedRuleSupport > 0) {
                return "Approved rule prior only: prioritize this pattern, but still re-validate current source evidence before reporting or suppressing.";
            }
            if (pocSuccessFeedback > 0 && falsePositiveFeedback == 0) {
                return "Prior only: historical PoC success exists; re-validate exploit preconditions and current-source reachability before reporting.";
            }
            if (pocFailureFeedback > 0 && confirmFeedback == 0) {
                return "Prior only: historical negative validation exists; verify whether the same mitigation, PoC failure condition or reachability break exists in current source before suppressing.";
            }
            if (falsePositiveFeedback > 0 && confirmFeedback == 0) {
                return "Prior only: historical false-positive feedback exists; verify whether the same mitigation or reachability break exists in current source before suppressing.";
            }
            if (confirmFeedback > 0 && falsePositiveFeedback == 0) {
                return "Prior only: historical confirmation exists; re-validate attacker control, impact and missing mitigation from current source before reporting.";
            }
            if (riskDowngradeFeedback > 0) {
                return "Prior only: historical risk downgrade exists; verify current impact before lowering severity.";
            }
            return "Prior only: use as attention guidance; re-validate from current source before reporting.";
        }

        private static String textStatic(JsonNode node, String key) {
            JsonNode value = node.path(key);
            return value.isMissingNode() || value.isNull() ? "" : value.asText("");
        }
    }

    private static final class RuleCandidateAccumulator {
        private final String vulnType;
        private final String ruleId;
        private final String filePattern;
        private final String httpPath;
        private final Set<String> jobs = new LinkedHashSet<>();
        private final List<Map<String, Object>> provenance = new ArrayList<>();
        private int findingSupport;
        private int confirmFeedback;
        private int falsePositiveFeedback;
        private int needsReviewFeedback;
        private int duplicateFeedback;
        private int riskDowngradeFeedback;
        private int missedFindingFeedback;
        private int pocSuccessFeedback;
        private int pocFailureFeedback;

        RuleCandidateAccumulator(
                String vulnType,
                String ruleId,
                String filePattern,
                String httpPath
        ) {
            this.vulnType = vulnType;
            this.ruleId = ruleId;
            this.filePattern = filePattern;
            this.httpPath = httpPath;
        }

        void add(JsonNode node) {
            String jobId = textStatic(node, "job_id");
            if (!jobId.isBlank()) {
                jobs.add(jobId);
            }
            String eventType = textStatic(node, "event_type");
            String feedback = textStatic(node, "feedback_verdict");
            if ("finding_observed".equals(eventType)) {
                findingSupport++;
            }
            if ("CONFIRM".equals(feedback)) {
                confirmFeedback++;
            } else if ("FALSE_POSITIVE".equals(feedback)) {
                falsePositiveFeedback++;
            } else if ("NEEDS_REVIEW".equals(feedback)) {
                needsReviewFeedback++;
            } else if ("DUPLICATE".equals(feedback)) {
                duplicateFeedback++;
            } else if ("RISK_DOWNGRADE".equals(feedback)) {
                riskDowngradeFeedback++;
            } else if ("MISSED_FINDING".equals(feedback)) {
                missedFindingFeedback++;
            } else if ("POC_SUCCESS".equals(feedback)) {
                pocSuccessFeedback++;
                confirmFeedback++;
            } else if ("POC_FAILURE".equals(feedback)) {
                pocFailureFeedback++;
                falsePositiveFeedback++;
            }
            if (provenance.size() < 5) {
                provenance.add(Map.of(
                        "job_id", jobId,
                        "event_type", eventType,
                        "feedback_verdict", feedback,
                        "learning_signal", textStatic(node, "learning_signal"),
                        "poc_status", textStatic(node, "poc_status"),
                        "file_path", textStatic(node, "file_path"),
                        "start_line", textStatic(node, "start_line"),
                        "http_path", textStatic(node, "http_path"),
                        "recorded_at", textStatic(node, "recorded_at")
                ));
            }
        }

        boolean shouldEmit() {
            return positiveSupportCount() >= 2
                    || confirmFeedback > 0
                    || falsePositiveFeedback > 0
                    || riskDowngradeFeedback > 0
                    || missedFindingFeedback > 0
                    || duplicateFeedback > 0;
        }

        int positiveSupportCount() {
            return findingSupport + confirmFeedback
                    + needsReviewFeedback + missedFindingFeedback;
        }

        int totalEvidenceCount() {
            return findingSupport + confirmFeedback
                    + needsReviewFeedback + falsePositiveFeedback
                    + duplicateFeedback + riskDowngradeFeedback
                    + missedFindingFeedback;
        }

        double confidenceScore() {
            double raw = findingSupport + confirmFeedback * 2.0
                    + needsReviewFeedback * 0.5
                    + missedFindingFeedback * 1.5
                    - falsePositiveFeedback * 1.5
                    - riskDowngradeFeedback * 0.5
                    - duplicateFeedback * 0.25;
            double bounded = Math.max(0.0, raw);
            return Math.round((bounded / Math.max(1.0, positiveSupportCount())) * 100.0) / 100.0;
        }

        String candidateId() {
            String base = (vulnType + "-" + ruleId + "-" + filePattern + "-" + httpPath)
                    .toLowerCase(Locale.ROOT)
                    .replaceAll("[^a-z0-9]+", "-")
                    .replaceAll("^-|-$", "");
            return base.isBlank() ? "rule-candidate" : base;
        }

        Map<String, Object> toMap() {
            Map<String, Object> candidate = new LinkedHashMap<>();
            candidate.put("schema_version", SCHEMA_VERSION);
            candidate.put("candidate_id", candidateId());
            candidate.put("status", "CANDIDATE");
            candidate.put("vuln_type", vulnType);
            candidate.put("rule_id", ruleId);
            candidate.put("file_pattern", filePattern);
            candidate.put("http_path", httpPath);
            candidate.put("support_count", positiveSupportCount());
            candidate.put("total_evidence_count", totalEvidenceCount());
            candidate.put("observed_finding_count", findingSupport);
            candidate.put("confirm_count", confirmFeedback);
            candidate.put("false_positive_count", falsePositiveFeedback);
            candidate.put("needs_review_count", needsReviewFeedback);
            candidate.put("duplicate_count", duplicateFeedback);
            candidate.put("risk_downgrade_count", riskDowngradeFeedback);
            candidate.put("missed_finding_count", missedFindingFeedback);
            candidate.put("poc_success_count", pocSuccessFeedback);
            candidate.put("poc_failure_count", pocFailureFeedback);
            candidate.put("job_count", jobs.size());
            candidate.put("confidence_score", confidenceScore());
            candidate.put("suggested_agent_guidance", guidance());
            candidate.put("provenance", provenance);
            candidate.put("policy",
                    "Candidate only: requires human approval before becoming an active rule.");
            return candidate;
        }

        private String guidance() {
            if (falsePositiveFeedback > 0 && confirmFeedback == 0) {
                return "When a similar " + vulnType
                        + " pattern appears, first verify whether the historical mitigation, PoC failure condition or reachability break is present before reporting.";
            }
            if (riskDowngradeFeedback > 0) {
                return "When a similar " + vulnType
                        + " pattern appears, verify current business impact before preserving the original severity.";
            }
            if (confirmFeedback > 0) {
                return "When a similar " + vulnType
                        + " pattern appears, prioritize validating attacker control, impact and missing mitigation from current source.";
            }
            return "When a similar " + vulnType
                    + " pattern appears, use this as an audit hypothesis and re-validate from current source.";
        }

        private static String textStatic(JsonNode node, String key) {
            JsonNode value = node.path(key);
            return value.isMissingNode() || value.isNull() ? "" : value.asText("");
        }
    }
}
