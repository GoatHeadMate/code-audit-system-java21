package com.huawei.audit.agent;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class SubagentDefinitionService {
    private final Path promptRoot = Path.of("hunter-prompts").toAbsolutePath().normalize();

    public void materialize(Path workDirectory, List<String> hunters) throws IOException {
        Path agentsDirectory = workDirectory.resolve(".claude").resolve("agents");
        Path knowledgeDirectory = workDirectory.resolve("hunter-knowledge");
        Files.createDirectories(agentsDirectory);
        Files.createDirectories(knowledgeDirectory);

        for (String hunter : hunters) {
            String dashed = hunter.replace('_', '-');
            Path sourcePrompt = promptRoot.resolve("audit-" + dashed + ".md");
            if (!Files.isRegularFile(sourcePrompt)) {
                continue;
            }

            // Copy specialist knowledge to work directory as a separate file
            Path knowledgeFile = knowledgeDirectory.resolve(dashed + ".md");
            Files.copy(sourcePrompt, knowledgeFile,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);

            // Agent definition stays lean; agent reads knowledge on demand
            String definition = """
                    ---
                    name: audit-%s
                    description: White-box %s specialist. Use only when the supervisor assigns this vulnerability category.
                    tools: Read, Glob, Grep
                    disallowedTools: Bash, Write, Edit, NotebookEdit, WebFetch, WebSearch
                    model: inherit
                    ---

                    You are the `%s` white-box audit subagent.

                    Mandatory execution contract:
                    - Analyze only the evidence file assigned by the supervisor and source
                      files under the provided source root.
                    - CodeQL has already run. Never execute CodeQL, shell commands, or
                      create files.
                    - Do not delegate to another agent.
                    - Validate candidates against source code and suppress false positives.
                    - Return exactly one JSON array. Each item must contain rule_id, title,
                      severity, confidence, file_path, start_line, message, evidence and
                      vuln_type. Return [] when no issue is confirmed.
                    - Do not use Markdown fences or explanatory text.

                    First action: Read your specialist knowledge file at
                    `hunter-knowledge/%s.md` — it contains judgment rules and analysis
                    guidance for this vulnerability category. Then read the evidence file
                    assigned by the supervisor.
                    """.formatted(
                    dashed,
                    hunter.replace('_', ' '),
                    hunter,
                    dashed
            );
            Files.writeString(
                    agentsDirectory.resolve("audit-" + dashed + ".md"),
                    definition
            );
        }
    }
}
