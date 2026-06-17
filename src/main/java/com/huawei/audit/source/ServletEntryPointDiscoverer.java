package com.huawei.audit.source;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.EnumDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.RecordDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.huawei.audit.analysis.EntryPointDiscoverer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class ServletEntryPointDiscoverer implements EntryPointDiscoverer {
    private static final Logger log =
            LoggerFactory.getLogger(ServletEntryPointDiscoverer.class);
    private static final Pattern IMPLBASE_SUFFIX = Pattern.compile("\\w+ImplBase");
    private static final Set<String> SERVLET_METHODS = Set.of(
            "doGet", "doPost", "doPut", "doDelete", "doPatch", "service"
    );
    private static final Map<String, List<String>> SERVLET_OPS = Map.of(
            "doGet", List.of("GET"),
            "doPost", List.of("POST"),
            "doPut", List.of("PUT"),
            "doDelete", List.of("DELETE"),
            "doPatch", List.of("PATCH"),
            "service", List.of("ANY")
    );
    private static final Set<String> WEBSOCKET_METHODS = Set.of(
            "handleMessage", "handleTextMessage",
            "handleBinaryMessage", "afterConnectionEstablished"
    );
    private static final Set<String> WEBSOCKET_LIFECYCLE = Set.of(
            "OnMessage", "OnOpen", "OnClose", "OnError"
    );
    private static final Set<String> SECURITY_ANNOTATIONS = Set.of(
            "PreAuthorize", "Secured", "RolesAllowed", "PermitAll", "DenyAll"
    );
    private static final Pattern DUBBO_IMPORT = Pattern.compile(
            "org\\.apache\\.dubbo|com\\.alibaba\\.dubbo"
    );

    private final JavaParser parser = new JavaParser(new ParserConfiguration()
            .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21));

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
    ) {
        String relativePath = sourceRoot.relativize(file)
                .toString()
                .replace('\\', '/');
        ParseResult<CompilationUnit> parsed;
        try {
            parsed = parser.parse(file);
        } catch (Exception exception) {
            log.warn("入口扫描跳过无法解析的文件 {}: {}",
                    relativePath, exception.getMessage());
            return;
        }
        if (parsed.getResult().isEmpty()) {
            log.warn("入口扫描跳过解析失败的文件 {}（{} 个语法问题）",
                    relativePath, parsed.getProblems().size());
            return;
        }
        CompilationUnit unit = parsed.getResult().get();
        boolean dubboImport = hasDubboImport(unit);
        for (TypeDeclaration<?> type : unit.findAll(TypeDeclaration.class)) {
            scanType(type, relativePath, dubboImport, result);
        }
    }

    private void scanType(
            TypeDeclaration<?> type,
            String relativePath,
            boolean dubboImport,
            List<DiscoveredEntryPoint> result
    ) {
        String className = type.getNameAsString();
        String extendsName = "";
        List<String> implementsNames = List.of();
        if (type instanceof ClassOrInterfaceDeclaration declaration) {
            extendsName = declaration.getExtendedTypes().isEmpty()
                    ? ""
                    : declaration.getExtendedTypes().get(0).getNameAsString();
            implementsNames = declaration.getImplementedTypes().stream()
                    .map(implemented -> implemented.getNameAsString())
                    .toList();
        } else if (type instanceof RecordDeclaration recordType) {
            implementsNames = recordType.getImplementedTypes().stream()
                    .map(implemented -> implemented.getNameAsString())
                    .toList();
        } else if (type instanceof EnumDeclaration enumType) {
            implementsNames = enumType.getImplementedTypes().stream()
                    .map(implemented -> implemented.getNameAsString())
                    .toList();
        }
        boolean classWebServlet = hasAnnotation(type.getAnnotations(), "WebServlet");
        boolean classServerEndpoint =
                hasAnnotation(type.getAnnotations(), "ServerEndpoint");
        boolean classDubbo = hasAnnotation(type.getAnnotations(), "DubboService")
                || (hasAnnotation(type.getAnnotations(), "Service") && dubboImport);
        String webServletRoute = classWebServlet
                ? routeOf(type.getAnnotations(), "WebServlet")
                : "";

        for (MethodDeclaration method : type.getMethods()) {
            String name = method.getNameAsString();
            int line = method.getBegin().map(position -> position.line).orElse(0);
            List<String> security = securityAnnotations(method.getAnnotations());

            if (SERVLET_METHODS.contains(name)
                    && (extendsName.equals("HttpServlet")
                            || implementsNames.contains("HttpServlet"))) {
                result.add(entry("HTTP", SERVLET_OPS.get(name), "", className,
                        name, relativePath, line, "servlet", security, "HIGH"));
            } else if (classWebServlet) {
                result.add(entry("HTTP", List.of("ANY"), webServletRoute, className,
                        name, relativePath, line, "servlet", security, "HIGH"));
            }

            if ("doFilter".equals(name) && implementsNames.contains("Filter")) {
                result.add(entry("HTTP_FILTER", List.of("FILTER"), "", className,
                        name, relativePath, line, "servlet", security, "HIGH"));
            }
            if ("preHandle".equals(name)
                    && implementsNames.contains("HandlerInterceptor")) {
                result.add(entry("HTTP_FILTER", List.of("INTERCEPTOR"), "", className,
                        name, relativePath, line, "spring-mvc", security, "MEDIUM"));
            }
            if (isWebSocketEntry(classServerEndpoint, implementsNames, method, name)) {
                result.add(entry("WEBSOCKET", List.of("MESSAGE"), "", className,
                        name, relativePath, line, "websocket", security, "HIGH"));
            }
            if (IMPLBASE_SUFFIX.matcher(extendsName).matches()
                    && !name.equals(className)
                    && !method.isStatic()
                    && !method.isAbstract()) {
                result.add(entry("GRPC", List.of("UNARY"), "", className,
                        name, relativePath, line, "grpc", security, "MEDIUM"));
            }
            if (classDubbo
                    || hasAnnotation(method.getAnnotations(), "DubboService")
                    || (hasAnnotation(method.getAnnotations(), "Service") && dubboImport)) {
                result.add(entry("RPC", List.of("DUBBO"), "", className,
                        name, relativePath, line, "dubbo", security, "MEDIUM"));
            }
            if ("run".equals(name)
                    && (implementsNames.contains("CommandLineRunner")
                            || implementsNames.contains("ApplicationRunner"))) {
                result.add(entry("LIFECYCLE", List.of("STARTUP"), "", className,
                        name, relativePath, line, "spring-lifecycle", security, "LOW"));
            }
            if (hasAnnotation(method.getAnnotations(), "PostConstruct")) {
                result.add(entry("LIFECYCLE", List.of("INIT"), "", className,
                        name, relativePath, line, "spring-lifecycle", security, "LOW"));
            }
        }
    }

    private boolean isWebSocketEntry(
            boolean classServerEndpoint,
            List<String> implementsNames,
            MethodDeclaration method,
            String name
    ) {
        if (classServerEndpoint
                && hasAnyAnnotation(method.getAnnotations(), WEBSOCKET_LIFECYCLE)) {
            return true;
        }
        return implementsNames.contains("WebSocketHandler")
                && WEBSOCKET_METHODS.contains(name);
    }

    private DiscoveredEntryPoint entry(
            String protocol,
            List<String> operations,
            String route,
            String className,
            String methodName,
            String filePath,
            int line,
            String framework,
            List<String> security,
            String confidence
    ) {
        return new DiscoveredEntryPoint(
                protocol, operations, route, className, methodName,
                filePath, line, framework, security, id(), confidence
        );
    }

    private String routeOf(List<AnnotationExpr> annotations, String name) {
        List<String> values = annotations.stream()
                .filter(annotation ->
                        simpleName(annotation.getNameAsString()).equals(name))
                .flatMap(annotation ->
                        annotation.findAll(StringLiteralExpr.class).stream())
                .map(StringLiteralExpr::getValue)
                .toList();
        return values.isEmpty() ? "" : String.join(",", values);
    }

    private List<String> securityAnnotations(List<AnnotationExpr> annotations) {
        return annotations.stream()
                .map(annotation -> simpleName(annotation.getNameAsString()))
                .filter(SECURITY_ANNOTATIONS::contains)
                .toList();
    }

    private boolean hasAnnotation(List<AnnotationExpr> annotations, String name) {
        return annotations.stream()
                .anyMatch(annotation ->
                        simpleName(annotation.getNameAsString()).equals(name));
    }

    private boolean hasAnyAnnotation(
            List<AnnotationExpr> annotations,
            Set<String> names
    ) {
        return annotations.stream()
                .map(annotation -> simpleName(annotation.getNameAsString()))
                .anyMatch(names::contains);
    }

    private boolean hasDubboImport(CompilationUnit unit) {
        return unit.getImports().stream()
                .anyMatch(importDeclaration ->
                        DUBBO_IMPORT.matcher(
                                importDeclaration.getNameAsString()).find());
    }

    private String simpleName(String name) {
        int separator = name.lastIndexOf('.');
        return separator >= 0 ? name.substring(separator + 1) : name;
    }
}
