package com.huawei.audit.source;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import com.huawei.audit.analysis.EntryPointDiscoverer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class AsyncEntryPointDiscoverer implements EntryPointDiscoverer {
    private static final Logger log =
            LoggerFactory.getLogger(AsyncEntryPointDiscoverer.class);
    private static final Map<String, String> PROTOCOLS = Map.of(
            "Scheduled", "scheduled",
            "KafkaListener", "message",
            "JmsListener", "message",
            "RabbitListener", "message",
            "EventListener", "event",
            "Async", "async"
    );
    private static final Set<String> SECURITY_ANNOTATIONS = Set.of(
            "PreAuthorize", "Secured", "RolesAllowed", "PermitAll", "DenyAll"
    );

    private final JavaParser parser = new JavaParser(new ParserConfiguration()
            .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21));

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
        for (TypeDeclaration<?> type : unit.findAll(TypeDeclaration.class)) {
            String className = type.getNameAsString();
            for (MethodDeclaration method : type.getMethods()) {
                AnnotationExpr trigger = method.getAnnotations().stream()
                        .filter(annotation -> PROTOCOLS.containsKey(
                                simpleName(annotation.getNameAsString())))
                        .findFirst()
                        .orElse(null);
                if (trigger == null) {
                    continue;
                }
                String triggerName = simpleName(trigger.getNameAsString());
                result.add(new DiscoveredEntryPoint(
                        PROTOCOLS.get(triggerName),
                        List.of(triggerName),
                        annotationArguments(trigger),
                        className,
                        method.getNameAsString(),
                        relativePath,
                        method.getBegin().map(position -> position.line).orElse(0),
                        "spring-async",
                        securityAnnotations(method.getAnnotations()),
                        id(),
                        "HIGH"
                ));
            }
        }
    }

    private String annotationArguments(AnnotationExpr annotation) {
        if (annotation instanceof SingleMemberAnnotationExpr single) {
            return single.getMemberValue().toString();
        }
        if (annotation instanceof NormalAnnotationExpr normal) {
            return normal.getPairs().stream()
                    .map(Object::toString)
                    .collect(Collectors.joining(", "));
        }
        return "";
    }

    private List<String> securityAnnotations(List<AnnotationExpr> annotations) {
        return annotations.stream()
                .map(annotation -> simpleName(annotation.getNameAsString()))
                .filter(SECURITY_ANNOTATIONS::contains)
                .toList();
    }

    private String simpleName(String name) {
        int separator = name.lastIndexOf('.');
        return separator >= 0 ? name.substring(separator + 1) : name;
    }
}
