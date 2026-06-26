package com.huawei.audit.agent;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.hunter.FindingParser;
import com.huawei.audit.job.JobLogBroker;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.UserMessage;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
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

    private final ClaudeAgentSupervisorModel model;
    private final ObjectMapper objectMapper;
    private final FindingParser findingParser;
    private final OrchestratorProperties properties;
    private final JobLogBroker logs;

    public SupervisorAgent(
            ClaudeAgentSupervisorModel model,
            ObjectMapper objectMapper,
            FindingParser findingParser,
            OrchestratorProperties properties,
            JobLogBroker logs
    ) {
        this.model = model;
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
                "[supervisor-agent] starting one AgentScope Java supervisor"
                        + " with " + agents.size() + " pre-defined agents: "
                        + String.join(", ", agents.keySet())
        );
        String response = model.supervise(
                job.workDir(),
                sourceRoot,
                List.of(
                        SystemMessage.from(systemPrompt()),
                        UserMessage.from(userPrompt(
                                sourceRoot,
                                techProfile,
                                candidates,
                                analysisSummary
                        ))
                ),
                agents,
                line -> logs.publish(job, line)
        );
        Files.writeString(
                job.workDir().resolve("supervisor-response.txt"),
                response
        );
        try {
            SupervisorEnvelope envelope = parseEnvelope(response, candidates);
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
        } catch (Exception parseException) {
            String preview = response == null ? "null"
                    : response.strip().substring(0, Math.min(200, response.strip().length()));
            String message = "supervisor response unparseable: "
                    + parseException.getMessage()
                    + " | response preview: " + preview;
            logs.publish(
                    job,
                    "[supervisor-agent] failed to parse supervisor response: "
                            + parseException.getMessage()
                            + " | response preview: " + preview
            );
            throw new IllegalStateException(message, parseException);
        }
    }

    private Map<String, ClaudeGateway.AgentDef> buildAgentDefs(
            Path workDirectory,
            Path sourceRoot,
            List<String> candidates,
            Map<String, String> evidenceManifest,
            Map<String, String> skillManifest
    ) throws IOException {
        Map<String, ClaudeGateway.AgentDef> agents = new LinkedHashMap<>();
        String sourceRootStr = sourceRoot.toAbsolutePath().normalize().toString();
        List<String> readOnlyTools = List.of("read_file", "glob_files", "grep_files");
        for (String hunter : candidates) {
            String taskPath = evidenceManifest.get(hunter);
            if (taskPath == null) {
                continue;
            }
            String baseHunter = baseHunterName(hunter);
            String skillName = skillManifest.get(baseHunter);
            List<String> skills = skillName == null
                    ? List.of()
                    : List.of(skillName);
            String skillRef = skillName == null ? "(none)" : skillName;
            String skillContent = skillName == null
                    ? "(none)"
                    : readSkillContent(workDirectory, skillName);
            String agentPrompt = SUBAGENT_PROMPT_TEMPLATE.formatted(
                    hunter,
                    skillRef,
                    taskPath,
                    sourceRootStr,
                    skillRef + "\n\n" + skillContent
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

    private String readSkillContent(Path workDirectory, String skillName)
            throws IOException {
        Path skill = workDirectory.resolve(".claude")
                .resolve("skills")
                .resolve(skillName)
                .resolve("SKILL.md");
        return Files.isRegularFile(skill) ? Files.readString(skill) : "(missing)";
    }

    private static String baseHunterName(String hunter) {
        int batchIdx = hunter.indexOf("_batch_");
        return batchIdx >= 0 ? hunter.substring(0, batchIdx) : hunter;
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
                File and memory tools are denied by policy. Delegate all source
                review to hunter subagents via agent_spawn.
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
                1. Your first action after reading the user prompt must be one or
                   more `agent_spawn` calls for selected hunter agents.
                2. Delegate each selected category to its matching pre-defined agent.
                3. Launch independent agents in parallel waves, never exceeding the
                   maximum parallel agents stated in the user prompt.
                4. Code execution, authorization, unsafe parsing, file operations, SSRF
                   and component vulnerabilities are mandatory when available.
                   When a category is split into batch agents (e.g., code_execution_batch_1,
                   code_execution_batch_2), ALL batches are mandatory — each contains a
                   unique non-overlapping subset of candidates.
                5. Delegate no more than the configured maximum and never invent names.
                6. If a subagent errors or times out, include that status in the
                   rationale and continue with the other returned results.
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
                9. Before finalizing, verify each subagent confirmed it reviewed all
                   candidate chunks. If a subagent skipped chunks, resume it.
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
        int maxParallelHunters = Math.min(
                candidates.size(),
                properties.maxPrimaryHunters()
                        + properties.maxAdditionalHunters()
        );
        String batchNote = hasBatches
                ? """

                BATCH AGENTS: Some categories have been split into parallel batches.
                You MUST delegate ALL batch agents for each category.
                Use as many waves as needed and never exceed the parallel-wave limit.
                """
                : "";
        return """
                Source root: %s

                Technology profile:
                %s

                Pre-defined hunter agents (invoke by exact name via agent_spawn):
                %s

                Total Hunters to delegate: %d
                Maximum parallel agents per wave: %d
                Intelligent selection enabled: %s
                %s
                White-box analysis summary (for cross-API chain reasoning):
                %s

                DELEGATION INSTRUCTIONS:
                Invoke each pre-defined agent by name with the AgentScope
                `agent_spawn` tool. Your first action must be one or more
                `agent_spawn` calls. File and memory tools are denied by policy.
                Delegate all source inspection to hunter subagents.
                All agent definitions already contain their judgment-rules skill,
                task file, and source root. You do not need to pass file paths in the prompt.

                Select the specialists appropriate for this project. When intelligent
                selection is disabled, delegate all available agents.
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

            Your category judgment rules are provided as a Skill named `%s`
            (severity thresholds, confidence, sanitizer and downgrade conditions).
            Invoke that skill with the Skill tool FIRST, before reviewing candidates.

            Your task file (candidate paths to review):
            %s

            Source root:
            %s

            Execution steps:
            1. Invoke your `%s` skill to load category-specific judgment rules.
            2. Read the task file to get all candidate-path chunks.
            3. Review EVERY candidate-path chunk and stored-candidate chunk. For
               authorization, also review every endpoint in `authorization_surface`.
            4. For each candidate, validate the entrypoint-to-sink path against source code.
            5. Use read_file/glob_files/grep_files to resolve ambiguous dispatch and missing source slices.
            6. Never execute shell commands, create files, or delegate to another agent.
            7. Return a single JSON object: {"chunks_reviewed": N, "findings": [...]}.
               Each finding must contain: rule_id, verdict, title, severity, confidence,
               file_path, start_line, message, evidence, vuln_type, http_method,
               http_path, entrypoint, reachability, discovery_source, data_flow_path.
               Use verdict values CONFIRM, DOWNGRADE, or NEEDS_REVIEW. Do not
               include SUPPRESS candidates in findings.
            8. No markdown fences, no explanatory text around the JSON.
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

    public record SupervisorResult(
            List<String> selectedHunters,
            String rationale,
            List<Map<String, Object>> findings
    ) { }
}
