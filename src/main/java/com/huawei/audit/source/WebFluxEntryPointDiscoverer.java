package com.huawei.audit.source;

import com.huawei.audit.analysis.EntryPointDiscoverer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class WebFluxEntryPointDiscoverer implements EntryPointDiscoverer {
    private static final Pattern CLASS_DECLARATION = Pattern.compile(
            "\\b(?:class|interface|record)\\s+(\\w+)"
    );
    private static final Pattern METHOD_NAME = Pattern.compile(
            "([A-Za-z_$][\\w$]*)\\s*\\("
    );
    private static final Pattern ROUTE_CALL = Pattern.compile(
            "\\b(GET|POST|PUT|DELETE|PATCH)\\s*\\(\\s*\"([^\"]*)\""
    );
    private static final Pattern WEBFLUX_IMPORT = Pattern.compile(
            "org\\.springframework\\.web\\.reactive"
    );

    @Override
    public String id() {
        return "webflux-router";
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
        if (!hasWebFluxImport(lines)) {
            return;
        }
        String relativePath = sourceRoot.relativize(file)
                .toString()
                .replace('\\', '/');
        String className = "";
        String currentMethod = "";

        for (int index = 0; index < lines.size(); index++) {
            String trimmed = lines.get(index).strip();

            Matcher classMatcher = CLASS_DECLARATION.matcher(trimmed);
            if (classMatcher.find()) {
                className = classMatcher.group(1);
                currentMethod = "";
                continue;
            }

            if (looksLikeMethod(trimmed)) {
                currentMethod = methodName(trimmed);
            }

            Matcher routeMatcher = ROUTE_CALL.matcher(trimmed);
            while (routeMatcher.find()) {
                String httpMethod = routeMatcher.group(1);
                String route = routeMatcher.group(2);
                result.add(new DiscoveredEntryPoint(
                        "HTTP",
                        List.of(httpMethod),
                        route,
                        className,
                        currentMethod,
                        relativePath,
                        index + 1,
                        "webflux",
                        List.of(),
                        id(),
                        "MEDIUM"
                ));
            }
        }
    }

    private boolean hasWebFluxImport(List<String> lines) {
        int limit = Math.min(lines.size(), 120);
        for (int i = 0; i < limit; i++) {
            if (WEBFLUX_IMPORT.matcher(lines.get(i)).find()) {
                return true;
            }
        }
        return false;
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
