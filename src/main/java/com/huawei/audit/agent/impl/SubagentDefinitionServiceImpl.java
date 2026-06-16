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
        return """
                ---
                name: %s
                description: White-box %s judgment rules — severity thresholds, \
                confidence, sanitizer and downgrade conditions. Load when reviewing \
                %s candidate paths before issuing a verdict.
                ---

                # White-Box Judgment Rules: %s

                Apply these category-specific rules to every candidate-path chunk and
                stored-candidate chunk listed in your task file. Java has already done
                broad entrypoint, call-edge and sink discovery; your role is the
                semantic verdict on controllability, sanitizers, dispatch,
                authentication, authorization, exploit conditions and false positives.

                %s
                """.formatted(
                skillName,
                hunter.replace('_', ' '),
                hunter.replace('_', ' '),
                hunter.replace('_', ' '),
                specialistKnowledge.strip()
        );
    }
}
