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
        Path skillsDir = workDirectory.resolve(".claude").resolve("skills");
        Files.createDirectories(skillsDir);

        Map<String, String> skillNames = new LinkedHashMap<>();

        for (String hunter : hunters) {
            String baseHunter = baseHunterName(hunter);
            if (skillNames.containsKey(baseHunter)) {
                continue;
            }
            String baseDashed = baseHunter.replace('_', '-');
            Path sourcePrompt = promptRoot.resolve("audit-" + baseDashed + ".md");
            if (!Files.isRegularFile(sourcePrompt)) {
                continue;
            }
            String specialistKnowledge = Files.readString(sourcePrompt);
            String skillName = "audit-" + baseDashed;
            Path skillDir = skillsDir.resolve(skillName);
            Files.createDirectories(skillDir);
            Files.writeString(
                    skillDir.resolve("SKILL.md"),
                    buildSkill(skillName, baseHunter, specialistKnowledge)
            );
            skillNames.put(baseHunter, skillName);
        }

        return Map.copyOf(skillNames);
    }

    static String baseHunterName(String hunter) {
        int batchIdx = hunter.indexOf("_batch_");
        return batchIdx >= 0 ? hunter.substring(0, batchIdx) : hunter;
    }

    private String buildSkill(
            String skillName, String hunter, String specialistKnowledge
    ) {
        String fallbackDescription = "White-box "
                + hunter.replace('_', ' ')
                + " judgment rules. Load when reviewing "
                + hunter.replace('_', ' ')
                + " candidate paths before issuing a verdict.";
        String description = extractUseWhen(specialistKnowledge, fallbackDescription);
        return """
                ---
                name: %s
                description: >
                %s
                ---

                %s
                """.formatted(
                skillName,
                indentYamlBlock(description),
                specialistKnowledge.strip()
        );
    }

    private static String extractUseWhen(String content, String fallback) {
        String marker = "## Use When";
        int markerStart = content.indexOf(marker);
        if (markerStart < 0) {
            return fallback;
        }
        int bodyStart = markerStart + marker.length();
        int nextSection = content.indexOf("\n## ", bodyStart);
        String body = nextSection < 0
                ? content.substring(bodyStart)
                : content.substring(bodyStart, nextSection);
        String description = body.strip();
        return description.isBlank() ? fallback : description;
    }

    private static String indentYamlBlock(String description) {
        return description.lines()
                .map(String::stripTrailing)
                .map(line -> "                  " + line)
                .reduce((left, right) -> left + "\n" + right)
                .orElse("");
    }
}
