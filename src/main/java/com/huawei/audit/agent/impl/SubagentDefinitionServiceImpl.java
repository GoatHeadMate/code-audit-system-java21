package com.huawei.audit.agent.impl;

import com.huawei.audit.agent.SubagentDefinitionService;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class SubagentDefinitionServiceImpl implements SubagentDefinitionService {
    private final Path promptRoot = Path.of("hunter-prompts")
            .toAbsolutePath()
            .normalize();

    @Override
    public Map<String, String> materialize(
            Path workDirectory, List<String> hunters, Map<String, String> taskManifest
    ) throws IOException {
        Path instructionsDir = workDirectory.resolve("instructions");
        Files.createDirectories(instructionsDir);

        Map<String, String> instructionPaths = new LinkedHashMap<>();

        for (String hunter : hunters) {
            String baseHunter = baseHunterName(hunter);
            if (instructionPaths.containsKey(baseHunter)) {
                continue;
            }
            String baseDashed = baseHunter.replace('_', '-');
            Path sourcePrompt = promptRoot.resolve("audit-" + baseDashed + ".md");
            if (!Files.isRegularFile(sourcePrompt)) {
                continue;
            }
            String specialistKnowledge = Files.readString(sourcePrompt);
            Path instructionFile = instructionsDir.resolve("audit-" + baseDashed + ".md");
            Files.writeString(instructionFile, buildInstruction(baseHunter, specialistKnowledge));
            instructionPaths.put(baseHunter, absolute(instructionFile));
        }

        return Map.copyOf(instructionPaths);
    }

    static String baseHunterName(String hunter) {
        int batchIdx = hunter.indexOf("_batch_");
        return batchIdx >= 0 ? hunter.substring(0, batchIdx) : hunter;
    }

    private String buildInstruction(String hunter, String specialistKnowledge) {
        return """
                # White-Box Audit Instruction: %s

                You are a white-box code audit subagent for the `%s` category.

                ## Execution Contract

                1. Read the TASK FILE whose path will be given to you in the prompt.
                2. Open and review EVERY candidate-path chunk and stored-candidate chunk.
                3. Java has already discovered entrypoints, methods, call edges and
                   dangerous sinks. Do not repeat an unbounded repository-wide scan.
                4. For each candidate, validate the proposed entrypoint-to-sink path
                   against source code. Follow only the files and unresolved edges needed
                   to reach a verdict.
                5. Determine whether request-controlled data actually reaches the sink,
                   including stored or asynchronous second-order flows.
                6. A stored candidate contains an HTTP write path and a later execution
                   path joined by a storage key. Confirm the exact entity field, database
                   column, mapper property, Redis key or equivalent mapping.
                7. Use Glob/Grep/Read to resolve ambiguous dispatch, inherited handlers,
                   framework filters, sanitizers and missing source slices.
                8. Never execute CodeQL, shell commands, or create files.
                9. Do not delegate to another agent.
                10. Validate every reported path against source code and suppress false
                    positives.

                ## Output Format

                Return exactly one JSON object with two keys:
                - "chunks_reviewed" (integer)
                - "findings" (array of finding objects)

                Each finding must contain: rule_id, title, severity, confidence,
                file_path, start_line, message, evidence, vuln_type, http_method,
                http_path, entrypoint, reachability, discovery_source, data_flow_path.

                Return {"chunks_reviewed": 0, "findings": []} when no issue is confirmed.
                Do not use Markdown fences or explanatory text around the JSON.

                ## Category-Specific Judgment Rules

                %s
                """.formatted(
                hunter.replace('_', ' '),
                hunter,
                specialistKnowledge.strip()
        );
    }

    private String absolute(Path path) {
        return path.toAbsolutePath().normalize().toString();
    }
}
