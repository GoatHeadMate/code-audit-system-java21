package com.huawei.audit.agent;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.hunter.FindingParser;
import com.huawei.audit.job.JobLogBroker;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.UserMessage;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class SupervisorAgent {
    private static final Set<String> MANDATORY = Set.of(
            "sql_injection",
            "command_injection",
            "authorization"
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
                Your job is to plan, delegate, review and aggregate. Do not perform every
                specialist analysis yourself.

                Rules:
                1. Delegate each selected category to its matching Agent subagent.
                2. Launch independent subagents in parallel in a single delegation wave
                   whenever possible.
                3. SQL injection, command injection and authorization are mandatory when
                   available.
                4. Delegate no more than the configured maximum and never invent names.
                5. Give each subagent its exact evidence file and source root.
                6. Subagents must use only Read/Glob/Grep. Never request Bash or CodeQL.
                7. If a subagent returns an agentId and says "use SendMessage to continue",
                   you MUST use SendMessage with that agentId to resume it. Never create
                   a new Agent for the same hunter — always continue the existing one.
                8. Review returned findings, remove duplicates and obvious false positives.
                9. Each finding MUST include these fields:
                   rule_id, title, severity (HIGH/MEDIUM/LOW), confidence (HIGH/MEDIUM/LOW),
                   vuln_type (e.g. SQL_INJECTION, SSRF, XSS), file_path, start_line,
                   message, evidence, data_flow_path (array of strings).
                   Omitting any of these fields makes the finding unparseable.
                10. Return one strict JSON object without Markdown:
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
                selection is disabled, delegate all available Hunters. Each evidence file
                already contains CodeQL results and query errors.
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
            candidates.stream()
                    .filter(MANDATORY::contains)
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
        try {
            JsonNode direct = objectMapper.readTree(stripped);
            if (direct.isObject()) {
                return direct;
            }
        } catch (Exception ignored) {
            // Extract the outer object below.
        }
        int start = stripped.indexOf('{');
        int end = stripped.lastIndexOf('}');
        if (start >= 0 && end > start) {
            JsonNode extracted = objectMapper.readTree(stripped.substring(start, end + 1));
            if (extracted.isObject()) {
                return extracted;
            }
        }
        throw new IllegalArgumentException(
                "supervisor did not return a JSON object"
        );
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
