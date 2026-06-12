package com.huawei.audit.source;

import com.huawei.audit.analysis.EntryPointDiscoverer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class ServletEntryPointDiscoverer implements EntryPointDiscoverer {
    private static final Pattern CLASS_DECL = Pattern.compile(
            "\\b(?:class|interface)\\s+(\\w+)"
                    + "(?:\\s+extends\\s+([\\w.]+))?"
                    + "(?:\\s+implements\\s+([\\w.,\\s]+))?"
    );
    private static final Pattern METHOD_NAME = Pattern.compile(
            "([A-Za-z_$][\\w$]*)\\s*\\("
    );
    private static final Pattern IMPLBASE_SUFFIX = Pattern.compile("\\w+ImplBase$");
    private static final Set<String> SERVLET_METHODS = Set.of(
            "doGet", "doPost", "doPut", "doDelete", "doPatch", "service"
    );
    private static final Set<String> DUBBO_ANNOTATIONS = Set.of("DubboService");
    private static final Pattern DUBBO_IMPORT = Pattern.compile(
            "org\\.apache\\.dubbo|com\\.alibaba\\.dubbo"
    );
    private static final Map<String, List<String>> SERVLET_OPS = Map.of(
            "doGet", List.of("GET"),
            "doPost", List.of("POST"),
            "doPut", List.of("PUT"),
            "doDelete", List.of("DELETE"),
            "doPatch", List.of("PATCH"),
            "service", List.of("ANY")
    );

    private final HttpAnnotationParser annotations = new HttpAnnotationParser();

    @Override
    public String id() {
        return "servlet-and-lifecycle";
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
        boolean hasDubboImport = hasDubboImport(lines);
        String currentClassName = "";
        String currentExtends = "";
        List<String> currentImplements = List.of();
        boolean classHasWebServlet = false;
        boolean classHasDubboService = false;
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

            Matcher classMatcher = CLASS_DECL.matcher(trimmed);
            if (classMatcher.find()) {
                currentClassName = classMatcher.group(1);
                currentExtends = classMatcher.group(2) == null
                        ? "" : simpleName(classMatcher.group(2));
                String implementsClause = classMatcher.group(3);
                currentImplements = implementsClause == null
                        ? List.of()
                        : parseImplements(implementsClause);
                classHasWebServlet = annotations.hasAny(
                        pending, "WebServlet");
                classHasDubboService = hasDubboAnnotation(pending, hasDubboImport);
                pending.clear();
                continue;
            }

            if (!pending.isEmpty() && looksLikeMethod(trimmed)) {
                String mName = methodName(trimmed);
                int lineNum = index + 1;

                if (SERVLET_METHODS.contains(mName)
                        && extendsOrImplements(
                                currentExtends, currentImplements,
                                "HttpServlet")) {
                    result.add(new DiscoveredEntryPoint(
                            "HTTP",
                            SERVLET_OPS.get(mName),
                            "",
                            currentClassName,
                            mName,
                            relativePath,
                            lineNum,
                            "servlet",
                            annotations.securityAnnotations(pending),
                            id(),
                            "HIGH"
                    ));
                } else if (classHasWebServlet) {
                    result.add(new DiscoveredEntryPoint(
                            "HTTP",
                            List.of("ANY"),
                            servletRoute(pending),
                            currentClassName,
                            mName,
                            relativePath,
                            lineNum,
                            "servlet",
                            annotations.securityAnnotations(pending),
                            id(),
                            "HIGH"
                    ));
                }

                if ("doFilter".equals(mName)
                        && implementsAnyOf(currentImplements, "Filter")) {
                    result.add(new DiscoveredEntryPoint(
                            "HTTP_FILTER",
                            List.of("FILTER"),
                            "",
                            currentClassName,
                            mName,
                            relativePath,
                            lineNum,
                            "servlet",
                            annotations.securityAnnotations(pending),
                            id(),
                            "HIGH"
                    ));
                }

                if ("preHandle".equals(mName)
                        && implementsAnyOf(
                                currentImplements, "HandlerInterceptor")) {
                    result.add(new DiscoveredEntryPoint(
                            "HTTP_FILTER",
                            List.of("INTERCEPTOR"),
                            "",
                            currentClassName,
                            mName,
                            relativePath,
                            lineNum,
                            "spring-mvc",
                            annotations.securityAnnotations(pending),
                            id(),
                            "MEDIUM"
                    ));
                }

                if (isWebSocketEntry(currentExtends, currentImplements,
                        pending, mName)) {
                    result.add(new DiscoveredEntryPoint(
                            "WEBSOCKET",
                            List.of("MESSAGE"),
                            "",
                            currentClassName,
                            mName,
                            relativePath,
                            lineNum,
                            "websocket",
                            annotations.securityAnnotations(pending),
                            id(),
                            "HIGH"
                    ));
                }

                if (IMPLBASE_SUFFIX.matcher(currentExtends).matches()
                        && !mName.equals(currentClassName)
                        && !isStaticOrAbstract(trimmed)) {
                    result.add(new DiscoveredEntryPoint(
                            "GRPC",
                            List.of("UNARY"),
                            "",
                            currentClassName,
                            mName,
                            relativePath,
                            lineNum,
                            "grpc",
                            annotations.securityAnnotations(pending),
                            id(),
                            "MEDIUM"
                    ));
                }

                if (classHasDubboService
                        || hasDubboAnnotation(pending, hasDubboImport)) {
                    result.add(new DiscoveredEntryPoint(
                            "RPC",
                            List.of("DUBBO"),
                            "",
                            currentClassName,
                            mName,
                            relativePath,
                            lineNum,
                            "dubbo",
                            annotations.securityAnnotations(pending),
                            id(),
                            "MEDIUM"
                    ));
                }

                if ("run".equals(mName)
                        && implementsAnyOf(currentImplements,
                                "CommandLineRunner",
                                "ApplicationRunner")) {
                    result.add(new DiscoveredEntryPoint(
                            "LIFECYCLE",
                            List.of("STARTUP"),
                            "",
                            currentClassName,
                            mName,
                            relativePath,
                            lineNum,
                            "spring-lifecycle",
                            annotations.securityAnnotations(pending),
                            id(),
                            "LOW"
                    ));
                }

                if (annotations.hasAny(pending, "PostConstruct")) {
                    result.add(new DiscoveredEntryPoint(
                            "LIFECYCLE",
                            List.of("INIT"),
                            "",
                            currentClassName,
                            mName,
                            relativePath,
                            lineNum,
                            "spring-lifecycle",
                            annotations.securityAnnotations(pending),
                            id(),
                            "LOW"
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

    private boolean extendsOrImplements(
            String extendsName,
            List<String> implementsList,
            String target
    ) {
        return target.equals(extendsName)
                || implementsList.contains(target);
    }

    private boolean implementsAnyOf(
            List<String> implementsList,
            String... targets
    ) {
        for (String target : targets) {
            if (implementsList.contains(target)) {
                return true;
            }
        }
        return false;
    }

    private boolean isWebSocketEntry(
            String extendsName,
            List<String> implementsList,
            List<HttpAnnotationParser.AnnotationRef> pending,
            String methodName
    ) {
        if (annotations.hasAny(pending, "ServerEndpoint")) {
            return true;
        }
        Set<String> wsMethods = Set.of(
                "handleMessage", "handleTextMessage",
                "handleBinaryMessage", "afterConnectionEstablished"
        );
        return implementsAnyOf(implementsList, "WebSocketHandler")
                && wsMethods.contains(methodName);
    }

    private boolean hasDubboAnnotation(
            List<HttpAnnotationParser.AnnotationRef> pending,
            boolean hasDubboImport
    ) {
        return pending.stream()
                .map(HttpAnnotationParser.AnnotationRef::name)
                .anyMatch(name -> DUBBO_ANNOTATIONS.contains(name)
                        || ("Service".equals(name) && hasDubboImport));
    }

    private boolean hasDubboImport(List<String> lines) {
        int limit = Math.min(lines.size(), 60);
        for (int i = 0; i < limit; i++) {
            if (DUBBO_IMPORT.matcher(lines.get(i)).find()) {
                return true;
            }
        }
        return false;
    }

    private String servletRoute(
            List<HttpAnnotationParser.AnnotationRef> pending
    ) {
        List<String> values = annotations.quotedValues(
                pending, "WebServlet");
        return values.isEmpty() ? "" : String.join(",", values);
    }

    private List<String> parseImplements(String clause) {
        List<String> result = new ArrayList<>();
        for (String part : clause.split(",")) {
            String name = part.strip();
            if (!name.isEmpty()) {
                result.add(simpleName(name));
            }
        }
        return List.copyOf(result);
    }

    private String simpleName(String qualified) {
        int dot = qualified.lastIndexOf('.');
        return dot < 0 ? qualified : qualified.substring(dot + 1);
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

    private boolean isStaticOrAbstract(String line) {
        return line.contains(" static ")
                || line.contains(" abstract ");
    }
}
