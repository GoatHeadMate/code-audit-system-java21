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
            Map<String, String> evidenceManifest
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
                                evidenceManifest
                        ))
                ),
                line -> logs.publish(job, line)
        );
        Files.writeString(
                job.workDir().resolve("supervisor-response.txt"),
                response
        );
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
    }

    private String systemPrompt() {
        return """
                You are the main enterprise white-box audit supervisor.

                You have native Claude Code Agent subagents named `audit-<hunter>`.
                Java has already built white-box candidate paths from external entrypoints
                through source call edges to dangerous sinks, including two-stage stored
                candidates that join an HTTP write path to an asynchronous execution path.
                Your job is to delegate semantic validation, review verdict quality and aggregate confirmed remote
                code-execution findings. Do not repeat broad source discovery yourself.

                Rules:
                1. Delegate each selected category to its matching Agent subagent.
                2. Launch independent subagents in parallel in a single delegation wave
                   whenever possible.
                3. Command injection, authorization, deserialization, file upload, H2 RCE,
                   Log4j JNDI, SSRF and SSTI are mandatory when available because they can
                   directly enable RCE or materially affect remote reachability.
                4. Delegate no more than the configured maximum and never invent names.
                5. Give each subagent its exact task file and source root. Require it to
                   review every candidate-path chunk in that task.
                   Stored-candidate chunks are mandatory and must be reviewed as joined
                   write/storage/read/execution flows.
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
                10. Before finalizing, check that delegated subagents reviewed all candidate
                    chunks assigned to them. Treat unresolved entrypoints and calls as
                    coverage limitations, not confirmed vulnerabilities.
                11. Return one strict JSON object without Markdown:
                   {
                     "selected_hunters": ["..."],
                     "rationale": "...",
                     "findings": [...]
                   }
                """;
    }

    private String userPrompt(
            Path sourceRoot,
            Map<String, Object> techProfile,
            List<String> candidates,
            Map<String, String> evidenceManifest
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
                properties.enabled()
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
        JsonNode fencedEnvelope = null;
        while (fenced.find()) {
            JsonNode candidate = parseCandidate(fenced.group(1));
            if (isEnvelope(candidate)) {
                fencedEnvelope = candidate;
            }
        }
        if (fencedEnvelope != null) {
            return fencedEnvelope;
        }

        // Fall back to every object start instead of the first one. Explanatory
        // text can contain expressions such as ${orderByClause} before the
        // actual JSON envelope.
        for (int start = stripped.lastIndexOf('{');
             start >= 0;
             start = stripped.lastIndexOf('{', start - 1)) {
            JsonNode candidate = parseCandidate(stripped.substring(start));
            if (isEnvelope(candidate)) {
                return candidate;
            }
        }

        throw new IllegalArgumentException(
                "supervisor did not return a JSON object"
        );
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
