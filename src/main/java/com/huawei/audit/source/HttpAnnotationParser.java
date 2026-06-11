package com.huawei.audit.source;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class HttpAnnotationParser {
    private static final Pattern ANNOTATION = Pattern.compile(
            "@(?:[\\w.]+\\.)?(\\w+)(?:\\s*\\((.*)\\))?"
    );
    private static final Pattern QUOTED = Pattern.compile("\"([^\"]*)\"");
    private static final Pattern REQUEST_METHOD = Pattern.compile(
            "RequestMethod\\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"
    );
    private static final Set<String> HTTP_ANNOTATIONS = Set.of(
            "RequestMapping", "GetMapping", "PostMapping", "PutMapping",
            "DeleteMapping", "PatchMapping", "GET", "POST", "PUT",
            "DELETE", "PATCH", "HEAD", "OPTIONS"
    );

    AnnotationBlock annotationBlock(List<String> lines, int start) {
        StringBuilder text = new StringBuilder(lines.get(start).strip());
        int balance = parenthesesBalance(lines.get(start));
        int end = start;
        while (balance > 0 && end + 1 < lines.size()) {
            end++;
            String next = lines.get(end).strip();
            text.append(' ').append(next);
            balance += parenthesesBalance(next);
        }
        return new AnnotationBlock(text.toString(), end);
    }

    List<AnnotationRef> parse(String text) {
        List<AnnotationRef> annotations = new ArrayList<>();
        Matcher matcher = ANNOTATION.matcher(text);
        while (matcher.find()) {
            annotations.add(new AnnotationRef(
                    matcher.group(1),
                    matcher.group(2) == null ? "" : matcher.group(2),
                    matcher.group()
            ));
        }
        return annotations;
    }

    boolean hasHttpAnnotation(List<AnnotationRef> annotations) {
        return annotations.stream()
                .map(AnnotationRef::name)
                .anyMatch(HTTP_ANNOTATIONS::contains);
    }

    List<String> httpMethods(List<AnnotationRef> annotations) {
        LinkedHashSet<String> methods = new LinkedHashSet<>();
        for (AnnotationRef annotation : annotations) {
            String name = annotation.name();
            if (Set.of(
                    "GET", "POST", "PUT", "DELETE",
                    "PATCH", "HEAD", "OPTIONS"
            ).contains(name)) {
                methods.add(name);
            } else if (name.endsWith("Mapping")
                    && !"RequestMapping".equals(name)) {
                methods.add(name.substring(
                        0,
                        name.length() - "Mapping".length()
                ).toUpperCase(Locale.ROOT));
            } else if ("RequestMapping".equals(name)) {
                Matcher matcher = REQUEST_METHOD.matcher(annotation.arguments());
                while (matcher.find()) {
                    methods.add(matcher.group(1));
                }
            }
        }
        return methods.isEmpty() ? List.of("ANY") : List.copyOf(methods);
    }

    List<String> paths(
            List<AnnotationRef> annotations,
            String... names
    ) {
        Set<String> accepted = Set.of(names);
        LinkedHashSet<String> paths = new LinkedHashSet<>();
        for (AnnotationRef annotation : annotations) {
            if (!accepted.contains(annotation.name())) {
                continue;
            }
            Matcher matcher = QUOTED.matcher(annotation.arguments());
            while (matcher.find()) {
                String candidate = matcher.group(1);
                if (candidate.startsWith("/") || candidate.isBlank()) {
                    paths.add(candidate);
                }
            }
        }
        return paths.isEmpty() ? List.of("") : List.copyOf(paths);
    }

    List<String> texts(List<AnnotationRef> annotations) {
        return annotations.stream().map(AnnotationRef::source).toList();
    }

    List<String> securityAnnotations(List<AnnotationRef> annotations) {
        return annotations.stream()
                .map(AnnotationRef::name)
                .filter(name -> name.equals("PreAuthorize")
                        || name.equals("Secured")
                        || name.equals("RolesAllowed")
                        || name.equals("PermitAll")
                        || name.equals("DenyAll"))
                .toList();
    }

    private int parenthesesBalance(String value) {
        int balance = 0;
        boolean quoted = false;
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (current == '"'
                    && (index == 0 || value.charAt(index - 1) != '\\')) {
                quoted = !quoted;
            } else if (!quoted && current == '(') {
                balance++;
            } else if (!quoted && current == ')') {
                balance--;
            }
        }
        return balance;
    }

    record AnnotationRef(String name, String arguments, String source) { }

    record AnnotationBlock(String text, int endLine) { }
}
