package com.huawei.audit.source;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.EnclosedExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.huawei.audit.analysis.EntryPointDiscoverer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class HttpEndpointScanner implements EntryPointDiscoverer {
    private static final Logger log =
            LoggerFactory.getLogger(HttpEndpointScanner.class);
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
        } catch (Exception exception) {
            log.warn("入口扫描跳过无法解析的文件 {}: {}",
                    relativePath, exception.getMessage());
            return;
        }
        if (result.getResult().isEmpty()) {
            log.warn("入口扫描跳过解析失败的文件 {}（{} 个语法问题）",
                    relativePath, result.getProblems().size());
        } else {
            CompilationUnit unit = result.getResult().get();
            String framework = detectFramework(unit);
            Map<String, String> constants = stringConstants(unit);
            // findAll covers class/interface/record/enum and nested types, each
            // keeping its own class-level mapping (no inner-class path bleed).
            for (TypeDeclaration<?> type : unit.findAll(TypeDeclaration.class)) {
                collectEndpoints(type, relativePath, framework, constants, endpoints);
            }
        }
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
            TypeDeclaration<?> type,
            String relativePath,
            String fileFramework,
            Map<String, String> constants,
            List<Endpoint> endpoints
    ) {
        String className = type.getNameAsString();
        Map<String, String> scopedConstants = scopedConstants(type, constants);
        boolean actuator = hasAnyAnnotation(type.getAnnotations(), ACTUATOR_ANNOTATIONS);
        String framework = actuator ? "spring-actuator" : fileFramework;
        List<String> classPaths = actuator
                ? actuatorClassPaths(type, scopedConstants)
                : pathsOf(type.getAnnotations(), CLASS_PATH_ANNOTATIONS, scopedConstants);

        for (MethodDeclaration method : type.getMethods()) {
            if (!hasAnyAnnotation(method.getAnnotations(), HTTP_ANNOTATIONS)) {
                continue;
            }
            String methodName = method.getNameAsString();
            int startLine = method.getBegin().map(position -> position.line).orElse(0);
            List<String> methods = httpMethods(method.getAnnotations());
            List<String> methodPaths = pathsOf(
                    method.getAnnotations(), METHOD_PATH_ANNOTATIONS, scopedConstants
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

    private List<String> actuatorClassPaths(
            TypeDeclaration<?> type,
            Map<String, String> constants
    ) {
        List<String> ids = stringValues(
                type.getAnnotations(),
                ACTUATOR_ANNOTATIONS,
                constants
        );
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
            Set<String> acceptedNames,
            Map<String, String> constants
    ) {
        LinkedHashSet<String> paths = new LinkedHashSet<>();
        for (AnnotationExpr annotation : annotations) {
            if (acceptedNames.contains(simpleName(annotation.getNameAsString()))) {
                paths.addAll(pathMemberStrings(annotation, constants));
            }
        }
        return paths.isEmpty() ? List.of("") : List.copyOf(paths);
    }

    private List<String> stringValues(
            List<AnnotationExpr> annotations,
            Set<String> acceptedNames,
            Map<String, String> constants
    ) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        for (AnnotationExpr annotation : annotations) {
            if (acceptedNames.contains(simpleName(annotation.getNameAsString()))) {
                values.addAll(allMemberStrings(annotation, constants));
            }
        }
        return List.copyOf(values);
    }

    // Actuator ids live in non-path members (e.g. @Endpoint(id = "admin")), so
    // collect string literals from every member, not just value/path.
    private List<String> allMemberStrings(
            AnnotationExpr annotation,
            Map<String, String> constants
    ) {
        List<String> values = new ArrayList<>();
        if (annotation instanceof SingleMemberAnnotationExpr single) {
            collectStrings(single.getMemberValue(), values, constants);
        } else if (annotation instanceof NormalAnnotationExpr normal) {
            for (MemberValuePair pair : normal.getPairs()) {
                collectStrings(pair.getValue(), values, constants);
            }
        }
        return values;
    }

    private List<String> pathMemberStrings(
            AnnotationExpr annotation,
            Map<String, String> constants
    ) {
        List<String> values = new ArrayList<>();
        if (annotation instanceof SingleMemberAnnotationExpr single) {
            collectStrings(single.getMemberValue(), values, constants);
        } else if (annotation instanceof NormalAnnotationExpr normal) {
            for (MemberValuePair pair : normal.getPairs()) {
                if (PATH_MEMBERS.contains(pair.getNameAsString())) {
                    collectStrings(pair.getValue(), values, constants);
                }
            }
        }
        return values;
    }

    private void collectStrings(
            Expression expression,
            List<String> out,
            Map<String, String> constants
    ) {
        if (expression instanceof StringLiteralExpr literal) {
            out.add(literal.getValue());
        } else if (expression instanceof ArrayInitializerExpr array) {
            array.getValues().forEach(value ->
                    collectStrings(value, out, constants));
        } else {
            constantString(expression, constants).ifPresent(out::add);
        }
    }

    private Map<String, String> stringConstants(CompilationUnit unit) {
        Map<String, Expression> expressions = new LinkedHashMap<>();
        for (TypeDeclaration<?> type : unit.findAll(TypeDeclaration.class)) {
            String typeName = type.getNameAsString();
            for (FieldDeclaration field : type.getFields()) {
                if (!field.isFinal()) {
                    continue;
                }
                for (VariableDeclarator variable : field.getVariables()) {
                    if (!"String".equals(simpleName(variable.getType().asString()))
                            || variable.getInitializer().isEmpty()) {
                        continue;
                    }
                    String name = variable.getNameAsString();
                    Expression initializer = variable.getInitializer().get();
                    expressions.putIfAbsent(name, initializer);
                    expressions.put(typeName + "." + name, initializer);
                }
            }
        }

        Map<String, String> constants = new LinkedHashMap<>();
        for (int pass = 0; pass < expressions.size(); pass++) {
            int before = constants.size();
            for (Map.Entry<String, Expression> entry : expressions.entrySet()) {
                if (constants.containsKey(entry.getKey())) {
                    continue;
                }
                constantString(entry.getValue(), constants)
                        .ifPresent(value -> constants.put(entry.getKey(), value));
            }
            if (constants.size() == before) {
                break;
            }
        }
        return Map.copyOf(constants);
    }

    private Map<String, String> scopedConstants(
            TypeDeclaration<?> type,
            Map<String, String> constants
    ) {
        Map<String, String> scoped = new LinkedHashMap<>(constants);
        String prefix = type.getNameAsString() + ".";
        constants.forEach((key, value) -> {
            if (key.startsWith(prefix)) {
                scoped.put(key.substring(prefix.length()), value);
            }
        });
        return Map.copyOf(scoped);
    }

    private Optional<String> constantString(
            Expression expression,
            Map<String, String> constants
    ) {
        if (expression instanceof StringLiteralExpr literal) {
            return Optional.of(literal.getValue());
        }
        if (expression instanceof NameExpr name) {
            return Optional.ofNullable(constants.get(name.getNameAsString()));
        }
        if (expression instanceof FieldAccessExpr fieldAccess) {
            String qualified = fieldAccess.getScope() + "."
                    + fieldAccess.getNameAsString();
            return Optional.ofNullable(constants.get(qualified));
        }
        if (expression instanceof EnclosedExpr enclosed) {
            return constantString(enclosed.getInner(), constants);
        }
        if (expression instanceof BinaryExpr binary
                && binary.getOperator() == BinaryExpr.Operator.PLUS) {
            Optional<String> left = constantString(binary.getLeft(), constants);
            Optional<String> right = constantString(binary.getRight(), constants);
            if (left.isPresent() && right.isPresent()) {
                return Optional.of(left.get() + right.get());
            }
        }
        return Optional.empty();
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
