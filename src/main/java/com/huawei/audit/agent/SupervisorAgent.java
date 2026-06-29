package com.huawei.audit.agent;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.hunter.FindingParser;
import com.huawei.audit.job.JobLogBroker;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class SupervisorAgent {
    private static final Pattern FENCED_JSON = Pattern.compile(
            "```(?:json)?\\s*([\\s\\S]*?)\\s*```",
            Pattern.CASE_INSENSITIVE
    );
    private static final List<String> MANDATORY = List.of(
            "code_execution",
            "authorization",
            "unsafe_parsing",
            "file_operations",
            "ssrf",
            "component_vulns"
    );
    private static final List<String> REVIEW_ARRAY_FIELDS = List.of(
            "authorization_surface",
            "endpoint_review_surface",
            "unresolved_entrypoints",
            "dependency_candidates",
            "component_candidates",
            "vulnerable_dependencies"
    );
    private static final int MAX_PARALLEL_HUNTER_SESSIONS = 2;

    private final ClaudeGateway gateway;
    private final ObjectMapper objectMapper;
    private final FindingParser findingParser;
    private final OrchestratorProperties properties;
    private final JobLogBroker logs;

    public SupervisorAgent(
            ClaudeGateway gateway,
            ObjectMapper objectMapper,
            FindingParser findingParser,
            OrchestratorProperties properties,
            JobLogBroker logs
    ) {
        this.gateway = gateway;
        this.objectMapper = objectMapper;
        this.findingParser = findingParser;
        this.properties = properties;
        this.logs = logs;
    }

    public SupervisorResult run(
            AuditJob job,
            Path sourceRoot,
            Map<String, Object> techProfile,
            List<String> candidates,
            Map<String, String> evidenceManifest,
            Map<String, String> skillManifest,
            Map<String, Object> analysisSummary
    ) throws Exception {
        Map<String, ClaudeGateway.AgentDef> agents = buildAgentDefs(
                job.workDir(), sourceRoot, candidates, evidenceManifest, skillManifest
        );
        logs.publish(
                job,
                "[supervisor-agent] starting AgentScope Java hunter sessions"
                        + " with " + agents.size() + " pre-defined agents: "
                        + String.join(", ", agents.keySet())
        );
        if (agents.isEmpty()) {
            String emptyResponse = """
                    {"selected_hunters":[],"rationale":"no evidence packages contain candidate review work","findings":[]}
                    """;
            Files.writeString(
                    job.workDir().resolve("supervisor-response.txt"),
                    emptyResponse
            );
            logs.publish(
                    job,
                    "[supervisor-agent] no evidence packages contain candidate review work; skipping AgentScope"
            );
            return new SupervisorResult(
                    List.of(),
                    "no evidence packages contain candidate review work",
                    List.of()
            );
        }
        SupervisorEnvelope envelope = superviseHunters(
                job,
                sourceRoot,
                techProfile,
                analysisSummary,
                agents
        );
        String response = responseJson(envelope);
        Files.writeString(
                job.workDir().resolve("supervisor-response.txt"),
                response
        );
        logs.publish(
                job,
                "[supervisor-agent] completed; delegated="
                        + String.join(", ", envelope.selectedHunters())
                        + ", findings=" + envelope.findings().size()
        );
        return new SupervisorResult(
                envelope.selectedHunters(),
                envelope.rationale(),
                envelope.findings()
        );
    }

    private SupervisorEnvelope superviseHunters(
            AuditJob job,
            Path sourceRoot,
            Map<String, Object> techProfile,
            Map<String, Object> analysisSummary,
            Map<String, ClaudeGateway.AgentDef> agents
    ) throws Exception {
        LinkedHashSet<String> selectedHunters = new LinkedHashSet<>();
        List<String> rationaleParts = new ArrayList<>();
        List<Map<String, Object>> findings = new ArrayList<>();
        List<String> failures = new ArrayList<>();
        List<Future<HunterSessionResult>> futures = new ArrayList<>();
        Semaphore sessionSlots = new Semaphore(MAX_PARALLEL_HUNTER_SESSIONS);

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (Map.Entry<String, ClaudeGateway.AgentDef> entry : agents.entrySet()) {
                futures.add(executor.submit(() -> superviseHunter(
                        job,
                        sourceRoot,
                        techProfile,
                        analysisSummary,
                        entry.getKey(),
                        entry.getValue(),
                        sessionSlots
                )));
            }

            for (Future<HunterSessionResult> future : futures) {
                HunterSessionResult result = await(future);
                if (result.failure() != null) {
                    failures.add(result.hunter() + ": " + result.failure());
                    rationaleParts.add(
                            result.hunter() + ": failed - " + result.failure()
                    );
                    continue;
                }
                SupervisorEnvelope envelope = result.envelope();
                selectedHunters.add(result.hunter());
                selectedHunters.addAll(envelope.selectedHunters());
                rationaleParts.add(result.hunter() + ": " + envelope.rationale());
                findings.addAll(envelope.findings());
            }
        }

        if (selectedHunters.isEmpty() && !failures.isEmpty()) {
            throw new IllegalStateException(
                    "all AgentScope hunter sessions failed: "
                            + String.join("; ", failures)
            );
        }
        return new SupervisorEnvelope(
                List.copyOf(selectedHunters),
                String.join(" | ", rationaleParts),
                findings
        );
    }

    private HunterSessionResult superviseHunter(
            AuditJob job,
            Path sourceRoot,
            Map<String, Object> techProfile,
            Map<String, Object> analysisSummary,
            String hunter,
            ClaudeGateway.AgentDef agentDef,
            Semaphore sessionSlots
    ) throws Exception {
        Map<String, ClaudeGateway.AgentDef> singleAgent = new LinkedHashMap<>();
        singleAgent.put(hunter, agentDef);
        String prompt = systemPrompt() + "\n\n"
                + userPrompt(sourceRoot, techProfile, List.of(hunter), analysisSummary);
        boolean slotAcquired = false;
        try {
            sessionSlots.acquire();
            slotAcquired = true;
            logs.publish(
                    job,
                    "[supervisor-agent] hunter " + hunter
                            + " acquired model slot (max_parallel="
                            + MAX_PARALLEL_HUNTER_SESSIONS + ")"
            );
            String response = gateway.supervise(
                    job.workDir(),
                    sourceRoot,
                    prompt,
                    singleAgent,
                    line -> logs.publish(job, line)
            );
            Files.writeString(
                    job.workDir().resolve(
                            "supervisor-response-" + safeFileName(hunter) + ".txt"
                    ),
                    response
            );
            SupervisorEnvelope envelope = parseEnvelopeWithPreview(
                    response,
                    List.of(hunter)
            );
            logs.publish(
                    job,
                    "[supervisor-agent] hunter " + hunter
                            + " completed; findings=" + envelope.findings().size()
            );
            return new HunterSessionResult(hunter, envelope, null);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return new HunterSessionResult(
                    hunter,
                    null,
                    "interrupted while waiting for model slot"
            );
        } catch (Exception exception) {
            logs.publish(
                    job,
                    "[supervisor-agent] hunter " + hunter
                            + " failed: " + exception.getMessage()
            );
            return new HunterSessionResult(hunter, null, exception.getMessage());
        } finally {
            if (slotAcquired) {
                sessionSlots.release();
            }
        }
    }

    private HunterSessionResult await(Future<HunterSessionResult> future) {
        try {
            return future.get();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(
                    "interrupted while waiting for AgentScope hunter session",
                    interrupted
            );
        } catch (ExecutionException executionException) {
            throw new IllegalStateException(
                    "AgentScope hunter session crashed",
                    executionException.getCause()
            );
        }
    }

    private String responseJson(SupervisorEnvelope envelope) throws Exception {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("selected_hunters", envelope.selectedHunters());
        response.put("rationale", envelope.rationale());
        response.put("findings", envelope.findings());
        return objectMapper.writeValueAsString(response);
    }

    private SupervisorEnvelope parseEnvelopeWithPreview(
            String response,
            List<String> activeCandidates
    ) throws Exception {
        try {
            return parseEnvelope(response, activeCandidates);
        } catch (Exception parseException) {
            String preview = response == null ? "null"
                    : response.strip().substring(0, Math.min(200, response.strip().length()));
            throw new IllegalStateException(
                    "supervisor response unparseable: "
                            + parseException.getMessage()
                            + " | response preview: " + preview,
                    parseException
            );
        }
    }

    private static String safeFileName(String value) {
        return value.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    private Map<String, ClaudeGateway.AgentDef> buildAgentDefs(
            Path workDirectory,
            Path sourceRoot,
            List<String> candidates,
            Map<String, String> evidenceManifest,
            Map<String, String> skillManifest
    ) {
        Map<String, ClaudeGateway.AgentDef> agents = new LinkedHashMap<>();
        String sourceRootStr = sourceRoot.toAbsolutePath().normalize().toString();
        List<String> readOnlyTools = List.of(
                "read_file",
                "glob_files",
                "grep_files",
                "load_skill_through_path"
        );
        for (String hunter : candidates) {
            String taskPath = evidenceManifest.get(hunter);
            if (taskPath == null) {
                continue;
            }
            if (!hasReviewWork(Path.of(taskPath))) {
                continue;
            }
            String baseHunter = baseHunterName(hunter);
            String skillName = skillManifest.get(baseHunter);
            List<String> skills = skillName == null
                    ? List.of()
                    : List.of(skillId(skillName));
            String skillRef = skillName == null ? "(none)" : skillName;
            String skillId = skillName == null ? "(none)" : skillId(skillName);
            String agentPrompt = SUBAGENT_PROMPT_TEMPLATE.formatted(
                    hunter,
                    skillRef,
                    skillId,
                    taskPath,
                    sourceRootStr,
                    skillId
            );
            agents.put(hunter, new ClaudeGateway.AgentDef(
                    "Audit " + hunter.replace('_', ' ')
                            + " vulnerabilities in the target project",
                    agentPrompt,
                    readOnlyTools,
                    null,
                    skills
            ));
        }
        return agents;
    }

    private boolean hasReviewWork(Path taskPath) {
        if (!Files.isRegularFile(taskPath)) {
            return true;
        }
        try {
            JsonNode task = objectMapper.readTree(taskPath.toFile());
            if (task.path("candidate_count").asInt(0) > 0
                    || task.path("stored_candidate_count").asInt(0) > 0) {
                return true;
            }
            if (task.path("endpoint_review_count").asInt(0) > 0) {
                return true;
            }
            for (String field : REVIEW_ARRAY_FIELDS) {
                JsonNode value = task.path(field);
                if (value.isArray() && value.size() > 0) {
                    return true;
                }
            }
            return false;
        } catch (IOException e) {
            return true;
        }
    }

    private static String baseHunterName(String hunter) {
        int batchIdx = hunter.indexOf("_batch_");
        String withoutBatch = batchIdx >= 0 ? hunter.substring(0, batchIdx) : hunter;
        int teamIdx = withoutBatch.indexOf("_team_");
        return teamIdx >= 0 ? withoutBatch.substring(0, teamIdx) : withoutBatch;
    }

    private static String skillId(String skillName) {
        return skillName + "_" + AgentScopeGateway.AUDIT_SKILL_SOURCE;
    }

    private String systemPrompt() {
        return """
                You are the main enterprise white-box audit supervisor.

                ════════════════════════════════════════════════════════════════
                OUTPUT FORMAT — MANDATORY, ZERO TOLERANCE
                Your ENTIRE final response must be a single JSON object.
                It must START with the character { and END with the character }.
                Do NOT write any text, markdown, code fences, summary tables,
                explanations, or commentary before or after the JSON.
                Violation = fatal parse error = entire audit fails.
                ════════════════════════════════════════════════════════════════

                ════════════════════════════════════════════════════════════════
                AGENT DELEGATION — USE AGENTSCOPE agent_spawn
                ════════════════════════════════════════════════════════════════
                All hunter subagents are pre-registered by name. Invoke them with
                the provided `agent_spawn` tool and the exact hunter name.
                Do NOT use file-reading, file-writing, or skill-loading tools
                yourself. Memory tools are disabled. Delegate all source review
                to hunter subagents via agent_spawn.
                Each agent already has its judgment-rules skill, task file and
                source root embedded in its definition. You only need to tell it
                to start and then read the returned result.
                ════════════════════════════════════════════════════════════════

                Java has already built white-box candidate paths from external entrypoints
                through source call edges to dangerous sinks, including two-stage stored
                candidates that join an HTTP write path to an asynchronous execution path.
                Your job is to delegate semantic validation, review verdict quality and
                aggregate confirmed findings. Do not repeat broad source discovery yourself.

                Rules:
                1. Your first action after reading the user prompt must be
                   a single `agent_spawn` call for the only registered hunter agent.
                2. CRITICAL: Issue EXACTLY ONE agent_spawn call in this session.
                   NEVER call agent_spawn more than once in this session — this
                   causes a fatal framework error.
                3. Wait for that hunter to return before synthesizing the final answer.
                4. Only registered hunter agents are available. Categories without
                   candidate paths or category-specific review surfaces are not
                   registered and must not be invented.
                   Code execution, authorization, unsafe parsing, file operations, SSRF
                   and component vulnerabilities are mandatory when registered.
                   When a category is split into batch agents (e.g., code_execution_batch_1,
                   code_execution_batch_2), ALL batches are mandatory — each contains a
                   unique non-overlapping subset of candidates.
                5. Delegate no more than the configured maximum and never invent names.
                6. If a subagent errors or times out, include that status in the
                   rationale and proceed with available results. NEVER re-spawn,
                   retry, or resume a timed-out or errored agent.
                7. Review returned findings, remove duplicates and obvious false positives.
                   Reject findings that name a sink but do not validate the candidate
                   entrypoint, dispatch path and attacker-controlled value flow.
                8. Each finding MUST include these fields:
                   rule_id, verdict (CONFIRM/DOWNGRADE/NEEDS_REVIEW), title,
                   severity (CRITICAL/HIGH/MEDIUM/LOW), confidence (HIGH/MEDIUM/LOW),
                   vuln_type (e.g. SQL_INJECTION, SSRF, XSS), file_path, start_line,
                   message, evidence, data_flow_path (array of strings), http_method,
                   http_path, entrypoint, reachability and discovery_source.
                   Omitting any of these fields makes the finding unparseable.
                   Do not return SUPPRESS items as findings; use them only to explain
                   why a candidate is not reported.
                9. Before finalizing, verify results from agents that completed
                   successfully. Do not re-spawn timed-out or errored agents.
                10. Return format:
                   {"selected_hunters":["..."],"rationale":"...","findings":[...]}
                11. After gathering all subagent findings, perform a CROSS-API CHAIN
                   COMPOSITION analysis before returning. Specifically:
                   a. If both SSRF and COMMAND_INJECTION/DESERIALIZATION findings exist,
                      check whether the SSRF target URL could reach the command injection
                      endpoint's internal path. Report the combined chain as a separate
                      CRITICAL finding with vuln_type "ATTACK_CHAIN".
                   b. Inspect proxy/forwarding utilities for automatic credential injection.
                   c. For weak whitelist (contains/startsWith) findings, reason about
                      concrete bypass techniques.
                   d. If an endpoint missing authentication can reach another endpoint
                      that has command execution, combine them into a single chain
                      finding showing the full unauthenticated-to-RCE path.
                """;
    }

    private String userPrompt(
            Path sourceRoot,
            Map<String, Object> techProfile,
            List<String> candidates,
            Map<String, Object> analysisSummary
    ) throws Exception {
        boolean hasBatches = candidates.stream().anyMatch(c -> c.contains("_batch_"));
        int totalHunters = hasBatches || !properties.enabled()
                ? candidates.size()
                : Math.min(
                        candidates.size(),
                        properties.maxPrimaryHunters()
                                + properties.maxAdditionalHunters()
                );
        int maxParallelHunters = 1;
        String batchNote = hasBatches
                ? """

                BATCH AGENTS: Some categories have been split into batches.
                You MUST delegate ALL batch agents for each category.
                """
                : "";
        return """
                Source root: %s

                Technology profile:
                %s

                Pre-defined hunter agents (invoke by exact name via agent_spawn):
                %s

                Total Hunters to delegate: %d
                Maximum agent_spawn calls per assistant turn: %d
                Intelligent selection enabled: %s
                %s
                White-box analysis summary (for cross-API chain reasoning):
                %s

                DELEGATION INSTRUCTIONS:
                Invoke the single pre-defined agent by name with the AgentScope
                `agent_spawn` tool. You MUST issue EXACTLY ONE agent_spawn
                call in this session. Do not spawn any other agent.
                Do NOT use file-reading, file-writing, or skill-loading tools
                yourself. Memory tools are disabled. Delegate all source
                inspection to hunters.
                All agent definitions already contain their judgment-rules skill,
                task file, and source root. You do not need to pass file paths in the prompt.

                Select the specialists appropriate for this project. When intelligent
                selection is disabled, delegate all available agents.

                ════════════════════════════════════════════════════════════════
                FINAL REMINDER — JSON ONLY
                After the agent_spawn result is collected, output EXACTLY ONE
                JSON object: {"selected_hunters":[...],"rationale":"...","findings":[...]}
                No prose, no markdown, no summary text before or after.
                Start your final message with { and end with }.
                ════════════════════════════════════════════════════════════════
                """.formatted(
                sourceRoot.toAbsolutePath().normalize(),
                objectMapper.writeValueAsString(techProfile),
                objectMapper.writeValueAsString(candidates),
                totalHunters,
                maxParallelHunters,
                properties.enabled(),
                batchNote,
                objectMapper.writerWithDefaultPrettyPrinter()
                        .writeValueAsString(analysisSummary)
        );
    }

    private static final String SUBAGENT_PROMPT_TEMPLATE = """
            You are a white-box code audit subagent for the `%s` category.

            Your category judgment rules are provided as an AgentScope skill named `%s`
            (severity thresholds, confidence, sanitizer and downgrade conditions).
            Your FIRST action must be:
            load_skill_through_path(skillId="%s", path="SKILL.md")
            Then follow the returned skill instructions before reviewing candidates.

            Your task file (candidate paths to review):
            %s

            Source root:
            %s

            Execution steps:
            1. Load your `%s` skill with load_skill_through_path before making judgments.
            2. Read the task file to get all candidate-path, stored-candidate,
               and endpoint-review chunks.
               If `team_name` / `team_focus` are present, treat them as the
               dynamic business-risk team assignment and keep the review scoped
               to that focus.
            3. Review EVERY candidate-path chunk, stored-candidate chunk, and
               endpoint in `endpoint_review_chunks` / `endpoint_review_surface`.
               For authorization, also review every endpoint in `authorization_surface`.
            4. For each endpoint-review item, read the referenced controller method
               and decide whether it is vulnerable, safe/sec, or not applicable.
               Treat `business_intents`, `risk_hypotheses`, and
               `suggested_poc_checks` as the harness-generated audit plan.
               Validate or reject each hypothesis from source evidence; do not
               execute PoC payloads in this static-review stage.
            5. For each candidate, validate the entrypoint-to-sink path against source code.
            6. Use read_file/glob_files/grep_files to resolve ambiguous dispatch and missing source slices.
            7. Never execute shell commands, create files, or delegate to another agent.
            8. Return a single JSON object: {"chunks_reviewed": N, "endpoint_reviewed": N, "findings": [...]}.
               Each finding must contain: rule_id, verdict, title, severity, confidence,
               file_path, start_line, message, evidence, vuln_type, http_method,
               http_path, entrypoint, reachability, discovery_source, data_flow_path.
               Use verdict values CONFIRM, DOWNGRADE, or NEEDS_REVIEW. Do not
               include SUPPRESS candidates in findings.
            9. No markdown fences, no explanatory text around the JSON.
            """;

    private SupervisorEnvelope parseEnvelope(
            String response,
            List<String> candidates
    ) throws Exception {
        JsonNode root = parseObject(response);
        LinkedHashSet<String> selected = new LinkedHashSet<>();
        boolean hasBatches = candidates.stream().anyMatch(c -> c.contains("_batch_"));
        if (!properties.enabled() || hasBatches) {
            selected.addAll(candidates);
        } else {
            for (String mandatory : MANDATORY) {
                candidates.stream()
                        .filter(c -> c.equals(mandatory)
                                || c.startsWith(mandatory + "_batch_"))
                        .forEach(selected::add);
            }
            JsonNode selectedNode = root.path("selected_hunters");
            if (selectedNode.isArray()) {
                selectedNode.forEach(node -> {
                    String hunter = node.asText();
                    if (candidates.contains(hunter)) {
                        selected.add(hunter);
                    }
                    candidates.stream()
                            .filter(c -> c.startsWith(hunter + "_batch_"))
                            .forEach(selected::add);
                });
            }
        }
        int limit = hasBatches || !properties.enabled()
                ? candidates.size()
                : Math.min(
                        candidates.size(),
                        properties.maxPrimaryHunters()
                                + properties.maxAdditionalHunters()
                );
        List<String> validatedSelection = new ArrayList<>(selected)
                .subList(0, Math.min(limit, selected.size()));

        String findingsJson = root.path("findings").toString();
        List<Map<String, Object>> findings = findingParser.parse(
                findingsJson,
                "supervisor"
        );
        return new SupervisorEnvelope(
                validatedSelection,
                root.path("rationale").asText("supervisor delegation"),
                findings
        );
    }

    private JsonNode parseObject(String text) throws Exception {
        String stripped = text == null ? "" : text.strip();
        JsonNode direct = parseCandidate(stripped);
        if (isEnvelope(direct)) {
            return direct;
        }

        Matcher fenced = FENCED_JSON.matcher(stripped);
        String lastFencedBody = null;
        while (fenced.find()) {
            String body = fenced.group(1);
            JsonNode candidate = parseCandidate(body);
            if (isEnvelope(candidate)) {
                return candidate;
            }
            if (body.contains("\"findings\"") && body.contains("\"selected_hunters\"")) {
                lastFencedBody = body;
            }
        }
        if (lastFencedBody != null) {
            JsonNode repaired = repairTruncatedJson(lastFencedBody);
            if (isEnvelope(repaired)) {
                return repaired;
            }
        }

        for (int start = stripped.lastIndexOf('{');
             start >= 0;
             start = stripped.lastIndexOf('{', start - 1)) {
            String slice = stripped.substring(start);
            JsonNode candidate = parseCandidate(slice);
            if (isEnvelope(candidate)) {
                return candidate;
            }
            if (slice.contains("\"findings\"") && slice.contains("\"selected_hunters\"")) {
                JsonNode repaired = repairTruncatedJson(slice);
                if (isEnvelope(repaired)) {
                    return repaired;
                }
            }
        }

        throw new IllegalArgumentException(
                "supervisor did not return a JSON object"
        );
    }

    private JsonNode repairTruncatedJson(String text) {
        String trimmed = text.strip();
        if (!trimmed.startsWith("{")) {
            int start = trimmed.indexOf('{');
            if (start < 0) {
                return null;
            }
            trimmed = trimmed.substring(start);
        }
        int braces = 0;
        int brackets = 0;
        boolean inString = false;
        boolean escaped = false;
        int lastSafeEnd = -1;
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\' && inString) {
                escaped = true;
                continue;
            }
            if (c == '"') {
                inString = !inString;
                continue;
            }
            if (inString) {
                continue;
            }
            if (c == '{') {
                braces++;
            } else if (c == '}') {
                braces--;
            } else if (c == '[') {
                brackets++;
            } else if (c == ']') {
                brackets--;
            }
            if (c == ',' || c == '}' || c == ']') {
                lastSafeEnd = i + 1;
            }
        }
        if (braces == 0 && brackets == 0) {
            return parseCandidate(trimmed);
        }
        if (lastSafeEnd <= 0) {
            return null;
        }
        StringBuilder repaired = new StringBuilder(trimmed.substring(0, lastSafeEnd));
        while (brackets > 0) {
            repaired.append(']');
            brackets--;
        }
        while (braces > 0) {
            repaired.append('}');
            braces--;
        }
        return parseCandidate(repaired.toString());
    }

    private JsonNode parseCandidate(String candidate) {
        try {
            return objectMapper.readTree(candidate.strip());
        } catch (Exception ignored) {
            return null;
        }
    }

    private boolean isEnvelope(JsonNode node) {
        return node != null
                && node.isObject()
                && node.path("findings").isArray()
                && node.path("selected_hunters").isArray();
    }

    private record SupervisorEnvelope(
            List<String> selectedHunters,
            String rationale,
            List<Map<String, Object>> findings
    ) { }

    private record HunterSessionResult(
            String hunter,
            SupervisorEnvelope envelope,
            String failure
    ) { }

    public record SupervisorResult(
            List<String> selectedHunters,
            String rationale,
            List<Map<String, Object>> findings
    ) { }
}
