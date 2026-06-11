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
public class HttpEndpointScanner implements EntryPointDiscoverer {
    private static final Pattern CLASS_DECLARATION = Pattern.compile(
            "\\b(?:class|interface|record)\\s+(\\w+)"
    );
    private final HttpAnnotationParser annotations = new HttpAnnotationParser();
    private final SourceHintScanner hintScanner = new SourceHintScanner();

    public ScanResult scan(Path sourceRoot) throws IOException {
        List<Endpoint> endpoints = new ArrayList<>();
        List<SourceHint> hints = new ArrayList<>();

        try (var files = Files.walk(sourceRoot)) {
            for (Path file : files
                    .filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().endsWith(".java"))
                    .sorted()
                    .toList()) {
                scanJavaFile(sourceRoot, file, endpoints, hints);
            }
        }
        return new ScanResult(List.copyOf(endpoints), List.copyOf(hints));
    }

    @Override
    public String id() {
        return "annotated-http";
    }

    @Override
    public List<DiscoveredEntryPoint> discover(Path sourceRoot) throws IOException {
        return scan(sourceRoot).endpoints().stream()
                .map(endpoint -> new DiscoveredEntryPoint(
                        "HTTP",
                        endpoint.httpMethods(),
                        endpoint.httpPath(),
                        endpoint.className(),
                        endpoint.methodName(),
                        endpoint.filePath(),
                        endpoint.startLine(),
                        endpoint.framework(),
                        endpoint.securityAnnotations(),
                        id(),
                        "HIGH"
                ))
                .toList();
    }

    private void scanJavaFile(
            Path sourceRoot,
            Path file,
            List<Endpoint> endpoints,
            List<SourceHint> hints
    ) throws IOException {
        List<String> lines = Files.readAllLines(file);
        String relativePath = sourceRoot.relativize(file)
                .toString()
                .replace('\\', '/');
        String framework = detectFramework(lines);
        String className = "";
        List<String> classPaths = List.of("");
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
                classPaths = annotations.paths(
                        pending,
                        "Path",
                        "RequestMapping"
                );
                pending.clear();
                continue;
            }

            if (!pending.isEmpty() && looksLikeMethod(trimmed)) {
                SignatureBlock signature = signatureBlock(lines, index);
                if (annotations.hasHttpAnnotation(pending)) {
                    String methodName = methodName(signature.text());
                    List<String> methods = annotations.httpMethods(pending);
                    List<String> methodPaths = annotations.paths(
                            pending,
                            "Path",
                            "RequestMapping",
                            "GetMapping",
                            "PostMapping",
                            "PutMapping",
                            "DeleteMapping",
                            "PatchMapping"
                    );
                    for (String classPath : classPaths) {
                        for (String methodPath : methodPaths) {
                            endpoints.add(new Endpoint(
                                    methods,
                                    joinPaths(classPath, methodPath),
                                    className,
                                    methodName,
                                    relativePath,
                                    index + 1,
                                    framework,
                                    signature.text(),
                                    annotations.texts(pending),
                                    annotations.securityAnnotations(pending)
                            ));
                        }
                    }
                }
                pending.clear();
                index = signature.endLine();
            } else if (!trimmed.isBlank()
                    && !trimmed.startsWith("//")
                    && !trimmed.startsWith("*")
                    && !trimmed.startsWith("/*")) {
                pending.clear();
            }

            hintScanner.scan(
                    relativePath,
                    index + 1,
                    lines.get(index),
                    hints
            );
        }
    }

    private SignatureBlock signatureBlock(List<String> lines, int start) {
        StringBuilder signature = new StringBuilder(lines.get(start).strip());
        int end = start;
        while (end + 1 < lines.size()
                && !signature.toString().contains("{")
                && !signature.toString().endsWith(";")) {
            end++;
            signature.append(' ').append(lines.get(end).strip());
        }
        return new SignatureBlock(
                signature.toString().replaceAll("\\s+", " ").strip(),
                end
        );
    }

    private boolean looksLikeMethod(String line) {
        return line.contains("(")
                && !line.startsWith("if ")
                && !line.startsWith("if(")
                && !line.startsWith("for ")
                && !line.startsWith("for(")
                && !line.startsWith("while ")
                && !line.startsWith("switch ");
    }

    private String methodName(String signature) {
        int parameterStart = signature.indexOf('(');
        String declaration = parameterStart < 0
                ? signature
                : signature.substring(0, parameterStart);
        Matcher matcher = Pattern.compile("([A-Za-z_$][\\w$]*)")
                .matcher(declaration);
        String result = "";
        while (matcher.find()) {
            result = matcher.group(1);
        }
        return result;
    }

    private String joinPaths(String classPath, String methodPath) {
        String combined = ("/" + classPath + "/" + methodPath)
                .replaceAll("/+", "/");
        return combined.length() > 1 && combined.endsWith("/")
                ? combined.substring(0, combined.length() - 1)
                : combined;
    }

    private String detectFramework(List<String> lines) {
        String imports = String.join("\n", lines.subList(0, Math.min(lines.size(), 120)));
        if (imports.contains("org.springframework.web.bind.annotation")) {
            return "spring-mvc";
        }
        if (imports.contains("com.huawei.bsp.roa.annotation")) {
            return "huawei-roa";
        }
        if (imports.contains("jakarta.ws.rs") || imports.contains("javax.ws.rs")) {
            return "jax-rs";
        }
        return "annotation-based";
    }

    private record SignatureBlock(String text, int endLine) { }

    public record Endpoint(
            List<String> httpMethods,
            String httpPath,
            String className,
            String methodName,
            String filePath,
            int startLine,
            String framework,
            String signature,
            List<String> annotations,
            List<String> securityAnnotations
    ) { }

    public record SourceHint(
            String category,
            String filePath,
            int line,
            String code
    ) { }

    public record ScanResult(
            List<Endpoint> endpoints,
            List<SourceHint> sourceHints
    ) { }
}
