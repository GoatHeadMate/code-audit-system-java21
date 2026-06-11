package com.huawei.audit.source;

import com.huawei.audit.analysis.EntryPointDiscoverer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class AsyncEntryPointDiscoverer implements EntryPointDiscoverer {
    private static final Pattern CLASS_DECLARATION = Pattern.compile(
            "\\b(?:class|interface|record)\\s+(\\w+)"
    );
    private static final Pattern METHOD_NAME = Pattern.compile(
            "([A-Za-z_$][\\w$]*)\\s*\\("
    );
    private static final Map<String, String> PROTOCOLS = Map.of(
            "Scheduled", "scheduled",
            "KafkaListener", "message",
            "JmsListener", "message",
            "RabbitListener", "message",
            "EventListener", "event",
            "Async", "async"
    );

    private final HttpAnnotationParser annotations = new HttpAnnotationParser();

    @Override
    public String id() {
        return "async-trigger";
    }

    @Override
    public List<DiscoveredEntryPoint> discover(Path sourceRoot)
            throws IOException {
        List<DiscoveredEntryPoint> result = new ArrayList<>();
        try (var files = Files.walk(sourceRoot)) {
            for (Path file : files
                    .filter(Files::isRegularFile)
                    .filter(path ->
                            path.getFileName().toString().endsWith(".java"))
                    .sorted()
                    .toList()) {
                scanFile(sourceRoot, file, result);
            }
        }
        return List.copyOf(result);
    }

    private void scanFile(
            Path sourceRoot,
            Path file,
            List<DiscoveredEntryPoint> result
    ) throws IOException {
        List<String> lines = Files.readAllLines(file);
        String relativePath = sourceRoot.relativize(file)
                .toString()
                .replace('\\', '/');
        String className = "";
        List<HttpAnnotationParser.AnnotationRef> pending = new ArrayList<>();

        for (int index = 0; index < lines.size(); index++) {
            String trimmed = lines.get(index).strip();
            if (trimmed.startsWith("@")) {
                HttpAnnotationParser.AnnotationBlock block =
                        annotations.annotationBlock(lines, index);
                pending.addAll(annotations.parse(block.text()));
                index = block.endLine();
                continue;
            }
            Matcher classMatcher = CLASS_DECLARATION.matcher(trimmed);
            if (classMatcher.find()) {
                className = classMatcher.group(1);
                pending.clear();
                continue;
            }
            if (!pending.isEmpty() && looksLikeMethod(trimmed)) {
                HttpAnnotationParser.AnnotationRef trigger = pending.stream()
                        .filter(annotation ->
                                PROTOCOLS.containsKey(annotation.name()))
                        .findFirst()
                        .orElse(null);
                if (trigger != null) {
                    result.add(new DiscoveredEntryPoint(
                            PROTOCOLS.get(trigger.name()),
                            List.of(trigger.name()),
                            trigger.arguments(),
                            className,
                            methodName(trimmed),
                            relativePath,
                            index + 1,
                            "spring-async",
                            annotations.securityAnnotations(pending),
                            id(),
                            "HIGH"
                    ));
                }
                pending.clear();
            } else if (!trimmed.isBlank()
                    && !trimmed.startsWith("//")
                    && !trimmed.startsWith("*")
                    && !trimmed.startsWith("/*")) {
                pending.clear();
            }
        }
    }

    private boolean looksLikeMethod(String line) {
        return line.contains("(")
                && !line.startsWith("if")
                && !line.startsWith("for")
                && !line.startsWith("while")
                && !line.startsWith("switch");
    }

    private String methodName(String declaration) {
        Matcher matcher = METHOD_NAME.matcher(declaration);
        String result = "";
        while (matcher.find()) {
            result = matcher.group(1);
        }
        return result;
    }
}
