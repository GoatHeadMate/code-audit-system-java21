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
import java.util.ArrayList;
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
            "command_injection",
            "authorization",
            "deserialization",
            "file_upload",
            "ssti",
            "h2_rce",
            "log4j_jndi",
            "ssrf"
    );

    private final ClaudeCodeSupervisorModel model;
    private final ObjectMapper objectMapper;
    private final FindingParser findingParser;
    private final OrchestratorProperties properties;
    private final JobLogBroker logs;

    public SupervisorAgent(
            ClaudeCodeSupervisorModel model,
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
            Map<String, Object> analysisSummary
    ) throws Exception {
        logs.publish(
                job,
                "[supervisor-agent] starting one Claude Code session with native subagents"
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
                                evidenceManifest,
                                analysisSummary
                        ))
                ),
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
            logs.publish(
                    job,
                    "[supervisor-agent] failed to parse supervisor response: "
                            + parseException.getMessage()
                            + " | response preview: " + preview
            );
            return new SupervisorResult(
                    candidates,
                    "supervisor response unparseable: " + parseException.getMessage(),
                    List.of()
            );
        }
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

                You have native Claude Code Agent subagents named `audit-<hunter>`.
                Java has already built white-box candidate paths from external entrypoints
                through source call edges to dangerous sinks, including two-stage stored
                candidates that join an HTTP write path to an asynchronous execution path.
                Your job is to delegate semantic validation, review verdict quality and
                aggregate confirmed findings. Do not repeat broad source discovery yourself.

                Rules:
                1. Delegate each selected category to its matching Agent subagent.
                2. Launch independent subagents in parallel in a single delegation wave
                   whenever possible.
                3. Command injection, authorization, deserialization, file upload, H2 RCE,
                   Log4j JNDI, SSRF and SSTI are mandatory when available because they can
                   directly enable RCE or materially affect remote reachability.
                4. Delegate no more than the configured maximum and never invent names.
                5. Give each subagent its exact task file path and source root path.
                   In the prompt to each subagent, include the literal string:
                   "Read the task file at <absolute path> first."
                   Require it to review EVERY candidate-path chunk and EVERY
                   stored-candidate chunk listed in that task.
                6. Subagents must use only Read/Glob/Grep. Never request Bash or CodeQL.
                7. If a subagent returns an agentId and says "use SendMessage to continue",
                   you MUST use SendMessage with that agentId to resume it. Never create
                   a new Agent for the same hunter — always continue the existing one.
                8. Review returned findings, remove duplicates and obvious false positives.
                   Reject findings that name a sink but do not validate the candidate
                   entrypoint, dispatch path and attacker-controlled value flow.
                9. Each finding MUST include these fields:
                   rule_id, title, severity (HIGH/MEDIUM/LOW), confidence (HIGH/MEDIUM/LOW),
                   vuln_type (e.g. SQL_INJECTION, SSRF, XSS), file_path, start_line,
                   message, evidence, data_flow_path (array of strings), http_method,
                   http_path, entrypoint, reachability and discovery_source.
                   Omitting any of these fields makes the finding unparseable.
                10. Before finalizing, verify each subagent confirmed it reviewed all
                    candidate chunks. If a subagent skipped chunks, resume it with
                    SendMessage. Treat unresolved entrypoints and calls as coverage
                    limitations, not confirmed vulnerabilities.
                11. Return format:
                   {"selected_hunters":["..."],"rationale":"...","findings":[...]}
                12. After gathering all subagent findings, perform a CROSS-API CHAIN
                   COMPOSITION analysis before returning. Specifically:
                   a. If both SSRF and COMMAND_INJECTION/DESERIALIZATION findings exist,
                      check whether the SSRF target URL could reach the command injection
                      endpoint's internal path. Report the combined chain as a separate
                      CRITICAL finding with vuln_type "ATTACK_CHAIN".
                   b. Inspect proxy/forwarding utilities (BackendRestClient, RestTemplate,
                      HttpClient wrappers) for automatic credential injection — if the
                      proxy auto-adds authentication headers (x-user-name, Authorization,
                      x-user-id, etc.), note this in the chain finding as it upgrades
                      SSRF from "can make requests" to "can make authenticated admin
                      requests to internal APIs".
                   c. For weak whitelist (contains/startsWith) findings, reason about
                      concrete bypass techniques: query parameter embedding
                      (?x=whitelisted_path), path traversal, fragment injection,
                      subdomain tricks. Include the bypass technique in the finding.
                   d. If an endpoint missing authentication can reach another endpoint
                      that has command execution, combine them into a single chain
                      finding showing the full unauthenticated-to-RCE path.
                """;
    }

    private String userPrompt(
            Path sourceRoot,
            Map<String, Object> techProfile,
            List<String> candidates,
            Map<String, String> evidenceManifest,
            Map<String, Object> analysisSummary
    ) throws Exception {
        int maxHunters = properties.enabled()
                ? Math.min(
                        candidates.size(),
                        properties.maxPrimaryHunters()
                                + properties.maxAdditionalHunters()
                )
                : candidates.size();
        return """
                Source root:
                %s

                Technology profile:
                %s

                Available Hunter subagents:
                %s

                Evidence file manifest:
                %s

                Maximum delegated Hunters: %d
                Intelligent selection enabled: %s

                White-box analysis summary (for cross-API chain reasoning):
                %s
                Use this summary to identify potential cross-API chains. For example,
                if both OUTBOUND_HTTP sinks (SSRF) and COMMAND_EXECUTION sinks exist,
                check whether SSRF can reach the command execution endpoints internally.

                Select the specialists appropriate for this project. When intelligent
                selection is disabled, delegate all available Hunters. Each evidence file is
                a bounded white-box review package containing precomputed entrypoint-to-sink
                candidate paths for that category. CodeQL is disabled. Java owns broad
                discovery and coverage; Hunters own semantic validation and false-positive
                suppression.
                """.formatted(
                sourceRoot.toAbsolutePath().normalize(),
                objectMapper.writeValueAsString(techProfile),
                objectMapper.writeValueAsString(candidates),
                objectMapper.writeValueAsString(evidenceManifest),
                maxHunters,
                properties.enabled(),
                objectMapper.writerWithDefaultPrettyPrinter()
                        .writeValueAsString(analysisSummary)
        );
    }

    private SupervisorEnvelope parseEnvelope(
            String response,
            List<String> candidates
    ) throws Exception {
        JsonNode root = parseObject(response);
        LinkedHashSet<String> selected = new LinkedHashSet<>();
        if (!properties.enabled()) {
            selected.addAll(candidates);
        } else {
            MANDATORY.stream()
                    .filter(candidates::contains)
                    .forEach(selected::add);
            JsonNode selectedNode = root.path("selected_hunters");
            if (selectedNode.isArray()) {
                selectedNode.forEach(node -> {
                    String hunter = node.asText();
                    if (candidates.contains(hunter)) {
                        selected.add(hunter);
                    }
                });
            }
        }
        int limit = properties.enabled()
                ? Math.min(
                        candidates.size(),
                        properties.maxPrimaryHunters()
                                + properties.maxAdditionalHunters()
                )
                : candidates.size();
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
