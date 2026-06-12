package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class ConfigTemplateScanner {
    private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([^}]+)}");
    private static final Pattern YAML_LINE = Pattern.compile(
            "^\\s*([\\w.-]+)\\s*:\\s*(.*)$"
    );
    private static final Pattern PROPS_LINE = Pattern.compile(
            "^\\s*([\\w.-]+)\\s*[=:]\\s*(.+)$"
    );
    private static final Pattern XML_ELEMENT = Pattern.compile(
            "<([\\w.-]+)[^>]*>\\s*([^<]*(?:\\$\\{[^}]+}[^<]*)*)\\s*</\\1>"
    );
    private static final Pattern XML_ATTR = Pattern.compile(
            "(?:value|command|script|exec|cmd)\\s*=\\s*\"([^\"]*\\$\\{[^}]+}[^\"]*)\"",
            Pattern.CASE_INSENSITIVE
    );
    private static final Set<String> CMD_KEYWORDS = Set.of(
            "bash", "sh ", "/bin/", "exec", "cmd", "python",
            "script", "shell", "powershell", "/bin/sh", "/bin/bash"
    );
    private static final Set<String> CONFIG_READ_PATTERNS = Set.of(
            "getProperty", "getString", "@Value",
            "@ConfigurationProperties", "environment.getProperty",
            "config.get", "props.get", "settings.get"
    );
    private static final Set<String> REPLACE_METHODS = Set.of(
            "replace", "replaceAll", "format"
    );

    record CommandTemplate(
            String configFile,
            String key,
            String templateValue,
            List<String> placeholders
    ) { }

    List<CommandTemplate> scan(Path sourceRoot) throws IOException {
        List<CommandTemplate> results = new ArrayList<>();
        try (var paths = Files.walk(sourceRoot)) {
            paths.filter(Files::isRegularFile)
                    .forEach(file -> {
                        String name = file.getFileName().toString();
                        try {
                            if (name.endsWith(".yml") || name.endsWith(".yaml")) {
                                results.addAll(scanYaml(sourceRoot, file));
                            } else if (name.endsWith(".properties")) {
                                results.addAll(scanProperties(sourceRoot, file));
                            } else if (name.endsWith(".xml")) {
                                results.addAll(scanXml(sourceRoot, file));
                            }
                        } catch (IOException ignored) {
                        }
                    });
        }
        return results;
    }

    List<Sink> findSinks(Path sourceRoot, SourceIndex index) throws IOException {
        List<CommandTemplate> templates = scan(sourceRoot);
        if (templates.isEmpty()) {
            return List.of();
        }
        Map<String, List<CommandTemplate>> templatesByDir = new LinkedHashMap<>();
        for (CommandTemplate template : templates) {
            String dir = template.configFile.contains("/")
                    ? template.configFile.substring(0, template.configFile.lastIndexOf('/'))
                    : "";
            templatesByDir.computeIfAbsent(dir, k -> new ArrayList<>()).add(template);
        }

        List<Sink> sinks = new ArrayList<>();
        int seq = 0;
        for (MethodNode method : index.methods()) {
            boolean hasConfigRead = hasConfigReadPattern(method);
            boolean hasReplaceCall = false;
            String replaceExpression = null;

            for (CallSite call : method.calls()) {
                if (REPLACE_METHODS.contains(call.methodName())) {
                    hasReplaceCall = true;
                    replaceExpression = call.expression();
                }
                if (!hasConfigRead && isConfigReadCall(call)) {
                    hasConfigRead = true;
                }
            }

            if (hasConfigRead && hasReplaceCall && replaceExpression != null) {
                for (CommandTemplate template : templates) {
                    if (containsCommandKeyword(template.templateValue())) {
                        String api = "ConfigTemplate:" + template.key() + "→replace→exec";
                        sinks.add(new Sink(
                                "config-tpl-sink-" + (++seq),
                                "COMMAND_EXECUTION",
                                api,
                                method.id(),
                                method.filePath(),
                                method.startLine(),
                                replaceExpression
                        ));
                        break;
                    }
                }
            }
        }
        return sinks;
    }

    private List<CommandTemplate> scanYaml(Path sourceRoot, Path file) throws IOException {
        List<CommandTemplate> results = new ArrayList<>();
        String relativePath = AnalysisTextUtils.relativePath(sourceRoot, file);
        List<String> lines = Files.readAllLines(file);
        List<String> parentKeys = new ArrayList<>();
        int lastIndent = -1;

        for (String line : lines) {
            if (line.isBlank() || line.strip().startsWith("#")) {
                continue;
            }
            int indent = countLeadingSpaces(line);
            Matcher matcher = YAML_LINE.matcher(line);
            if (matcher.matches()) {
                String key = matcher.group(1);
                String value = matcher.group(2).strip();
                if (value.startsWith("\"") && value.endsWith("\"")) {
                    value = value.substring(1, value.length() - 1);
                }
                if (indent <= lastIndent) {
                    int levelsToPop = (lastIndent - indent) / 2 + 1;
                    for (int i = 0; i < levelsToPop && !parentKeys.isEmpty(); i++) {
                        parentKeys.remove(parentKeys.size() - 1);
                    }
                }
                if (value.isEmpty()) {
                    parentKeys.add(key);
                    lastIndent = indent;
                } else {
                    String fullKey = buildFullKey(parentKeys, key);
                    if (containsPlaceholder(value) && containsCommandKeyword(value)) {
                        results.add(new CommandTemplate(
                                relativePath, fullKey, value, extractPlaceholders(value)
                        ));
                    }
                }
            }
        }
        return results;
    }

    private int countLeadingSpaces(String line) {
        int count = 0;
        for (char c : line.toCharArray()) {
            if (c == ' ') {
                count++;
            } else if (c == '\t') {
                count += 2;
            } else {
                break;
            }
        }
        return count;
    }

    private String buildFullKey(List<String> parentKeys, String key) {
        if (parentKeys.isEmpty()) {
            return key;
        }
        return String.join(".", parentKeys) + "." + key;
    }

    private List<CommandTemplate> scanProperties(Path sourceRoot, Path file) throws IOException {
        List<CommandTemplate> results = new ArrayList<>();
        String relativePath = AnalysisTextUtils.relativePath(sourceRoot, file);
        List<String> lines = Files.readAllLines(file);
        for (String line : lines) {
            Matcher matcher = PROPS_LINE.matcher(line);
            if (matcher.matches()) {
                String key = matcher.group(1);
                String value = matcher.group(2).strip();
                if (containsPlaceholder(value) && containsCommandKeyword(value)) {
                    results.add(new CommandTemplate(
                            relativePath, key, value, extractPlaceholders(value)
                    ));
                }
            }
        }
        return results;
    }

    private List<CommandTemplate> scanXml(Path sourceRoot, Path file) throws IOException {
        List<CommandTemplate> results = new ArrayList<>();
        String relativePath = AnalysisTextUtils.relativePath(sourceRoot, file);
        String content;
        try {
            content = Files.readString(file);
        } catch (Exception e) {
            return results;
        }

        Matcher elementMatcher = XML_ELEMENT.matcher(content);
        while (elementMatcher.find()) {
            String key = elementMatcher.group(1);
            String value = elementMatcher.group(2).strip();
            if (containsPlaceholder(value) && containsCommandKeyword(value)) {
                results.add(new CommandTemplate(
                        relativePath, key, value, extractPlaceholders(value)
                ));
            }
        }

        Matcher attrMatcher = XML_ATTR.matcher(content);
        while (attrMatcher.find()) {
            String value = attrMatcher.group(1);
            if (containsPlaceholder(value) && containsCommandKeyword(value)) {
                results.add(new CommandTemplate(
                        relativePath, "attribute", value, extractPlaceholders(value)
                ));
            }
        }
        return results;
    }

    private boolean hasConfigReadPattern(MethodNode method) {
        String signature = method.signature() != null ? method.signature() : "";
        String className = method.className() != null ? method.className() : "";
        String combined = signature + " " + className;
        for (String pattern : CONFIG_READ_PATTERNS) {
            if (combined.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    private boolean isConfigReadCall(CallSite call) {
        String expr = call.expression() != null ? call.expression() : "";
        String method = call.methodName() != null ? call.methodName() : "";
        return method.equals("getProperty") || method.equals("getString")
                || expr.contains("@Value") || expr.contains("@ConfigurationProperties")
                || expr.contains("environment.getProperty");
    }

    private boolean containsPlaceholder(String value) {
        return PLACEHOLDER.matcher(value).find();
    }

    private boolean containsCommandKeyword(String value) {
        String lower = value.toLowerCase(java.util.Locale.ROOT);
        for (String keyword : CMD_KEYWORDS) {
            if (lower.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    private List<String> extractPlaceholders(String value) {
        List<String> placeholders = new ArrayList<>();
        Matcher matcher = PLACEHOLDER.matcher(value);
        while (matcher.find()) {
            placeholders.add(matcher.group(1));
        }
        return placeholders;
    }
}
