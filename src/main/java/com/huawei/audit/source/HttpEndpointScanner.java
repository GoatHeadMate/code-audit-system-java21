package com.huawei.audit.source;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.huawei.audit.analysis.EntryPointDiscoverer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class HttpEndpointScanner implements EntryPointDiscoverer {
    private static final Set<String> HTTP_ANNOTATIONS = Set.of(
            "RequestMapping", "GetMapping", "PostMapping", "PutMapping",
            "DeleteMapping", "PatchMapping", "GET", "POST", "PUT",
            "DELETE", "PATCH", "HEAD", "OPTIONS", "ReadOperation",
            "WriteOperation", "DeleteOperation"
    );
    private static final Set<String> JAXRS_METHODS = Set.of(
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
    );
    private static final Set<String> METHOD_PATH_ANNOTATIONS = Set.of(
            "Path", "RequestMapping", "GetMapping", "PostMapping",
            "PutMapping", "DeleteMapping", "PatchMapping"
    );
    private static final Set<String> CLASS_PATH_ANNOTATIONS = Set.of(
            "Path", "RequestMapping"
    );
    private static final Set<String> ACTUATOR_ANNOTATIONS = Set.of(
            "Endpoint", "WebEndpoint", "ControllerEndpoint",
            "RestControllerEndpoint"
    );
    private static final Set<String> SECURITY_ANNOTATIONS = Set.of(
            "PreAuthorize", "Secured", "RolesAllowed", "PermitAll", "DenyAll"
    );
    // Members carrying a route; everything else (produces/consumes/headers/...)
    // is deliberately ignored so MIME types never leak into the path.
    private static final Set<String> PATH_MEMBERS = Set.of("value", "path");
    private static final Pattern REQUEST_METHOD = Pattern.compile(
            "RequestMethod\\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"
    );

    private final JavaParser parser = new JavaParser(new ParserConfiguration()
            .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21));
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
        String relativePath = sourceRoot.relativize(file)
                .toString()
                .replace('\\', '/');

        ParseResult<CompilationUnit> result;
        try {
            result = parser.parse(file);
        } catch (Exception ignored) {
            return;
        }
        result.getResult().ifPresent(unit -> {
            String framework = detectFramework(unit);
            // findAll visits nested classes independently, so each type keeps
            // its own class-level mapping (no inner-class path bleed).
            for (ClassOrInterfaceDeclaration type
                    : unit.findAll(ClassOrInterfaceDeclaration.class)) {
                collectEndpoints(type, relativePath, framework, endpoints);
            }
        });
        scanHints(file, relativePath, hints);
    }

    private void scanHints(
            Path file,
            String relativePath,
            List<SourceHint> hints
    ) throws IOException {
        List<String> lines = Files.readAllLines(file);
        for (int index = 0; index < lines.size(); index++) {
            hintScanner.scan(relativePath, index + 1, lines.get(index), hints);
        }
    }

    private void collectEndpoints(
            ClassOrInterfaceDeclaration type,
            String relativePath,
            String fileFramework,
            List<Endpoint> endpoints
    ) {
        String className = type.getNameAsString();
        boolean actuator = hasAnyAnnotation(type.getAnnotations(), ACTUATOR_ANNOTATIONS);
        String framework = actuator ? "spring-actuator" : fileFramework;
        List<String> classPaths = actuator
                ? actuatorClassPaths(type)
                : pathsOf(type.getAnnotations(), CLASS_PATH_ANNOTATIONS);

        for (MethodDeclaration method : type.getMethods()) {
            if (!hasAnyAnnotation(method.getAnnotations(), HTTP_ANNOTATIONS)) {
                continue;
            }
            String methodName = method.getNameAsString();
            int startLine = method.getBegin().map(position -> position.line).orElse(0);
            List<String> methods = httpMethods(method.getAnnotations());
            List<String> methodPaths = pathsOf(
                    method.getAnnotations(), METHOD_PATH_ANNOTATIONS
            );
            List<String> security = securityAnnotations(method.getAnnotations());
            List<String> annotationTexts = method.getAnnotations().stream()
                    .map(Object::toString)
                    .toList();
            String signature = method.getDeclarationAsString(true, false, false);

            for (String classPath : classPaths) {
                for (String methodPath : methodPaths) {
                    endpoints.add(new Endpoint(
                            methods,
                            joinPaths(classPath, methodPath),
                            className,
                            methodName,
                            relativePath,
                            startLine,
                            framework,
                            signature,
                            annotationTexts,
                            security
                    ));
                }
            }
        }
    }

    private List<String> actuatorClassPaths(ClassOrInterfaceDeclaration type) {
        List<String> ids = stringValues(type.getAnnotations(), ACTUATOR_ANNOTATIONS);
        if (ids.isEmpty()) {
            return List.of("/actuator");
        }
        return ids.stream().map(id -> "/actuator/" + id).toList();
    }

    private List<String> httpMethods(List<AnnotationExpr> annotations) {
        LinkedHashSet<String> methods = new LinkedHashSet<>();
        for (AnnotationExpr annotation : annotations) {
            String name = simpleName(annotation.getNameAsString());
            if (JAXRS_METHODS.contains(name)) {
                methods.add(name);
            } else if ("ReadOperation".equals(name)) {
                methods.add("GET");
            } else if ("WriteOperation".equals(name)) {
                methods.add("POST");
            } else if ("DeleteOperation".equals(name)) {
                methods.add("DELETE");
            } else if (name.endsWith("Mapping") && !"RequestMapping".equals(name)) {
                methods.add(name.substring(0, name.length() - "Mapping".length())
                        .toUpperCase(Locale.ROOT));
            } else if ("RequestMapping".equals(name)) {
                Matcher matcher = REQUEST_METHOD.matcher(annotation.toString());
                while (matcher.find()) {
                    methods.add(matcher.group(1));
                }
            }
        }
        return methods.isEmpty() ? List.of("ANY") : List.copyOf(methods);
    }

    /**
     * Collects route segments from the {@code value}/{@code path} members of the
     * accepted annotations. Unlike the old regex scanner this does NOT require a
     * leading slash, so relative paths like {@code @GetMapping("users")} survive;
     * members such as {@code produces}/{@code consumes} are ignored by name.
     */
    private List<String> pathsOf(
            List<AnnotationExpr> annotations,
            Set<String> acceptedNames
    ) {
        LinkedHashSet<String> paths = new LinkedHashSet<>();
        for (AnnotationExpr annotation : annotations) {
            if (acceptedNames.contains(simpleName(annotation.getNameAsString()))) {
                paths.addAll(pathMemberStrings(annotation));
            }
        }
        return paths.isEmpty() ? List.of("") : List.copyOf(paths);
    }

    private List<String> stringValues(
            List<AnnotationExpr> annotations,
            Set<String> acceptedNames
    ) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        for (AnnotationExpr annotation : annotations) {
            if (acceptedNames.contains(simpleName(annotation.getNameAsString()))) {
                values.addAll(allMemberStrings(annotation));
            }
        }
        return List.copyOf(values);
    }

    // Actuator ids live in non-path members (e.g. @Endpoint(id = "admin")), so
    // collect string literals from every member, not just value/path.
    private List<String> allMemberStrings(AnnotationExpr annotation) {
        List<String> values = new ArrayList<>();
        if (annotation instanceof SingleMemberAnnotationExpr single) {
            collectStrings(single.getMemberValue(), values);
        } else if (annotation instanceof NormalAnnotationExpr normal) {
            for (MemberValuePair pair : normal.getPairs()) {
                collectStrings(pair.getValue(), values);
            }
        }
        return values;
    }

    private List<String> pathMemberStrings(AnnotationExpr annotation) {
        List<String> values = new ArrayList<>();
        if (annotation instanceof SingleMemberAnnotationExpr single) {
            collectStrings(single.getMemberValue(), values);
        } else if (annotation instanceof NormalAnnotationExpr normal) {
            for (MemberValuePair pair : normal.getPairs()) {
                if (PATH_MEMBERS.contains(pair.getNameAsString())) {
                    collectStrings(pair.getValue(), values);
                }
            }
        }
        return values;
    }

    private void collectStrings(Expression expression, List<String> out) {
        if (expression instanceof StringLiteralExpr literal) {
            out.add(literal.getValue());
        } else if (expression instanceof ArrayInitializerExpr array) {
            // Cross-class constants resolve to nothing here (pure AST); the
            // endpoint is still emitted with the remaining segments rather
            // than dropped.
            array.getValues().forEach(value -> collectStrings(value, out));
        }
    }

    private List<String> securityAnnotations(List<AnnotationExpr> annotations) {
        return annotations.stream()
                .map(annotation -> simpleName(annotation.getNameAsString()))
                .filter(SECURITY_ANNOTATIONS::contains)
                .toList();
    }

    private boolean hasAnyAnnotation(
            List<AnnotationExpr> annotations,
            Set<String> names
    ) {
        return annotations.stream()
                .map(annotation -> simpleName(annotation.getNameAsString()))
                .anyMatch(names::contains);
    }

    private String detectFramework(CompilationUnit unit) {
        for (var importDeclaration : unit.getImports()) {
            String imported = importDeclaration.getNameAsString();
            if (imported.contains("org.springframework.web.bind.annotation")) {
                return "spring-mvc";
            }
            if (imported.contains("com.huawei.bsp.roa.annotation")) {
                return "huawei-roa";
            }
            if (imported.contains("jakarta.ws.rs") || imported.contains("javax.ws.rs")) {
                return "jax-rs";
            }
        }
        return "annotation-based";
    }

    private String joinPaths(String classPath, String methodPath) {
        String combined = ("/" + classPath + "/" + methodPath)
                .replaceAll("/+", "/");
        return combined.length() > 1 && combined.endsWith("/")
                ? combined.substring(0, combined.length() - 1)
                : combined;
    }

    private String simpleName(String name) {
        int separator = name.lastIndexOf('.');
        return separator >= 0 ? name.substring(separator + 1) : name;
    }

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
