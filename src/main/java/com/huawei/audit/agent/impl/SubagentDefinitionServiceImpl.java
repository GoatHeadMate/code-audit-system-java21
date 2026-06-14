package com.huawei.audit.agent.impl;

import com.huawei.audit.agent.SubagentDefinitionService;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Service;

@Service
public class SubagentDefinitionServiceImpl implements SubagentDefinitionService {
    private final Path promptRoot = Path.of("hunter-prompts")
            .toAbsolutePath()
            .normalize();

    @Override
    public void materialize(Path workDirectory, List<String> hunters)
            throws IOException {
        Path agentsDirectory = workDirectory.resolve(".claude").resolve("agents");
        Path skillsDirectory = workDirectory.resolve(".claude").resolve("skills");
        Files.createDirectories(agentsDirectory);
        Files.createDirectories(skillsDirectory);

        Set<String> materializedSkills = new LinkedHashSet<>();

        for (String hunter : hunters) {
            String baseHunter = baseHunterName(hunter);
            String baseDashed = baseHunter.replace('_', '-');
            String skillName = "audit-" + baseDashed;
            Path sourcePrompt = promptRoot.resolve("audit-" + baseDashed + ".md");
            if (!Files.isRegularFile(sourcePrompt)) {
                continue;
            }

            if (materializedSkills.add(skillName)) {
                String specialistKnowledge = Files.readString(sourcePrompt);
                Path skillDirectory = skillsDirectory.resolve(skillName);
                Files.createDirectories(skillDirectory);
                Files.writeString(
                        skillDirectory.resolve("SKILL.md"),
                        skillDefinition(skillName, baseHunter, specialistKnowledge)
                );
            }

            String dashed = hunter.replace('_', '-');
            Files.writeString(
                    agentsDirectory.resolve("audit-" + dashed + ".md"),
                    agentDefinition(dashed, skillName, baseHunter)
            );
        }
    }

    static String baseHunterName(String hunter) {
        int batchIdx = hunter.indexOf("_batch_");
        return batchIdx >= 0 ? hunter.substring(0, batchIdx) : hunter;
    }

    private String agentDefinition(
            String dashed,
            String skillName,
            String hunter
    ) {
        return """
                ---
                name: audit-%s
                description: White-box %s specialist. Use only when the supervisor assigns this vulnerability category.
                tools: Read, Glob, Grep
                disallowedTools: Bash, Write, Edit, NotebookEdit, WebFetch, WebSearch
                model: inherit
                skills:
                  - %s
                ---

                You are the `%s` white-box audit subagent.

                FIRST ACTION — before reading any task file or source code, invoke
                your `%s` skill to load the category-specific judgment
                rules (severity thresholds, sink patterns, downgrade conditions).
                These rules are mandatory for every verdict you produce.

                Mandatory execution contract:
                - Start from the assigned task file and review every candidate-path
                  and stored-candidate chunk listed in it.
                - Java has already discovered entrypoints, methods, call edges and
                  dangerous sinks. Do not repeat an unbounded repository-wide scan.
                - For each candidate, validate the proposed entrypoint-to-sink path
                  against source code. Follow only the files and unresolved edges needed
                  to reach a verdict.
                - Determine whether request-controlled data actually reaches the sink,
                  including stored or asynchronous second-order flows.
                - A stored candidate contains an HTTP write path and a later execution
                  path joined by a storage key. Confirm the exact entity field, database
                  column, mapper property, Redis key or equivalent mapping. Matching only
                  the same Repository is not sufficient for a finding.
                - For expression engines such as MVEL, SpEL, OGNL, Groovy, Velocity and
                  FreeMarker, inspect compile/bind/concatenation steps and the final
                  execution API. Confirm whether the stored value controls executable
                  syntax rather than only data variables.
                - Use Glob/Grep/Read to resolve ambiguous dispatch, inherited handlers,
                  framework filters, sanitizers and missing source slices.
                - Never execute CodeQL, shell commands, or create files.
                - Do not delegate to another agent.
                - Distinguish unauthenticated, authenticated and privileged reachability.
                  A missing method-level check is not proof of unauthenticated access when
                  a global filter may exist.
                - Validate every reported path against source code and suppress false
                  positives.
                - If the task has no candidates for this category, inspect only its
                  unresolved entrypoints for obvious analyzer gaps, then return [].
                - Return exactly one JSON object with two keys:
                  "chunks_reviewed" (integer — how many candidate + stored-candidate
                  chunk files you actually opened and read) and
                  "findings" (array of finding objects).
                  Each finding must contain rule_id, title, severity, confidence,
                  file_path, start_line, message, evidence and vuln_type. Also include
                  http_method, http_path, entrypoint, reachability, discovery_source
                  and data_flow_path when applicable.
                  Return {"chunks_reviewed": 0, "findings": []} when no issue is
                  confirmed.
                - Do not use Markdown fences or explanatory text.
                """                .formatted(
                dashed,
                hunter.replace('_', ' '),
                skillName,
                hunter,
                skillName
        );
    }

    private String skillDefinition(
            String skillName,
            String hunter,
            String specialistKnowledge
    ) {
        return """
                ---
                name: %s
                description: Audit every HTTP interface and its source call chain for %s vulnerabilities. Use only for the matching white-box audit Subagent.
                user-invocable: false
                ---

                Follow the candidate path package from the assigned task file. Apply the
                category-specific judgment rules below while treating any CodeQL-specific
                filenames as historical guidance about useful source/sink patterns. CodeQL
                output is not available and must not be required. Java performs broad,
                reproducible entrypoint and call-path discovery; your role is semantic
                validation of controllability, sanitization, dispatch, authentication,
                authorization, exploit conditions and false positives.

                %s
                """.formatted(
                skillName,
                hunter.replace('_', ' '),
                specialistKnowledge.strip()
        );
    }
}
