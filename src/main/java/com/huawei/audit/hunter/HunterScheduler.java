package com.huawei.audit.hunter;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
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
        List<String> available = ORDERED_HUNTERS.stream()
                .filter(hunter -> Files.exists(
                        promptRoot.resolve("audit-" + hunter.replace('_', '-') + ".md")
                ))
                .toList();

        Set<String> boosted = new LinkedHashSet<>();
        boosted.add("command_injection");
        boosted.add("authorization");

        String orm = String.valueOf(techProfile.getOrDefault("orm", ""));
        if (orm.toLowerCase(Locale.ROOT).contains("mybatis")
                || orm.toLowerCase(Locale.ROOT).contains("jpa")
                || orm.toLowerCase(Locale.ROOT).contains("hibernate")) {
            boosted.add("sql_injection");
        }

        @SuppressWarnings("unchecked")
        List<Map<String, String>> deps = (List<Map<String, String>>)
                techProfile.getOrDefault("dependencies", List.of());

        if (hasDep(deps, "h2")) boosted.add("h2_rce");
        if (hasDep(deps, "log4j")) boosted.add("log4j_jndi");
        if (hasDep(deps, "fastjson") || hasDep(deps, "xstream")
                || hasDep(deps, "snakeyaml")) boosted.add("deserialization");
        if (hasDep(deps, "freemarker") || hasDep(deps, "velocity")
                || hasDep(deps, "thymeleaf")) boosted.add("ssti");
        if (hasDep(deps, "actuator")) boosted.add("actuator");

        List<String> result = new ArrayList<>();
        for (String hunter : available) {
            if (boosted.contains(hunter)) result.add(hunter);
        }
        for (String hunter : available) {
            if (!boosted.contains(hunter)) result.add(hunter);
        }
        return List.copyOf(result);
    }

    private boolean hasDep(List<Map<String, String>> deps, String keyword) {
        String lower = keyword.toLowerCase(Locale.ROOT);
        return deps.stream()
                .flatMap(dep -> dep.values().stream())
                .map(v -> v.toLowerCase(Locale.ROOT))
                .anyMatch(v -> v.contains(lower));
    }
}
