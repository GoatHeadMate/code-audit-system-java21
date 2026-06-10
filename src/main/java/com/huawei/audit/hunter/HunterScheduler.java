package com.huawei.audit.hunter;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class HunterScheduler {
    private static final List<String> ORDERED_HUNTERS = List.of(
            "command_injection",
            "sql_injection",
            "log4j_jndi",
            "path_traversal",
            "xss",
            "actuator",
            "file_upload",
            "h2_rce",
            "ssrf",
            "ssti",
            "xxe",
            "authorization",
            "crlf_injection",
            "deserialization",
            "open_redirect"
    );

    private final Path promptRoot = Path.of("hunter-prompts").toAbsolutePath().normalize();

    public List<String> schedule(Map<String, Object> techProfile) {
        return ORDERED_HUNTERS.stream()
                .filter(hunter -> Files.exists(
                        promptRoot.resolve("audit-" + hunter.replace('_', '-') + ".md")
                ))
                .toList();
    }
}
