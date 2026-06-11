package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class MyBatisXmlScanner {
    private static final Pattern NAMESPACE = Pattern.compile(
            "<mapper\\s+namespace\\s*=\\s*\"([^\"]+)\"",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SQL_ELEMENT = Pattern.compile(
            "<(select|insert|update|delete)\\s+[^>]*id\\s*=\\s*\"([^\"]+)\"[^>]*>"
                    + "([\\s\\S]*?)</\\1>",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern UNSAFE_INTERPOLATION = Pattern.compile(
            "\\$\\{[^}]+}"
    );

    record UnsafeMapper(String interfaceName, String methodName,
                        String xmlFile, String snippet) { }

    List<UnsafeMapper> scan(Path sourceRoot) throws IOException {
        List<UnsafeMapper> results = new ArrayList<>();
        List<Path> xmlFiles;
        try (var paths = Files.walk(sourceRoot)) {
            xmlFiles = paths
                    .filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().endsWith(".xml"))
                    .toList();
        }
        for (Path xmlFile : xmlFiles) {
            String content;
            try {
                content = Files.readString(xmlFile);
            } catch (Exception ignored) {
                continue;
            }
            Matcher nsMatcher = NAMESPACE.matcher(content);
            if (!nsMatcher.find()) {
                continue;
            }
            String namespace = nsMatcher.group(1);
            String simpleName = namespace.contains(".")
                    ? namespace.substring(namespace.lastIndexOf('.') + 1)
                    : namespace;
            String relativePath = AnalysisTextUtils.relativePath(
                    sourceRoot, xmlFile
            );
            Matcher sqlMatcher = SQL_ELEMENT.matcher(content);
            while (sqlMatcher.find()) {
                String methodName = sqlMatcher.group(2);
                String body = sqlMatcher.group(3);
                if (UNSAFE_INTERPOLATION.matcher(body).find()) {
                    String snippet = body.strip();
                    if (snippet.length() > 200) {
                        snippet = snippet.substring(0, 200) + "...";
                    }
                    results.add(new UnsafeMapper(
                            simpleName, methodName, relativePath, snippet
                    ));
                }
            }
        }
        return results;
    }

    List<Sink> findSinks(
            Path sourceRoot,
            SourceIndex index
    ) throws IOException {
        List<UnsafeMapper> unsafeMethods = scan(sourceRoot);
        if (unsafeMethods.isEmpty()) {
            return List.of();
        }
        Map<String, Set<String>> unsafeByInterface = new LinkedHashMap<>();
        Map<String, UnsafeMapper> lookupMap = new LinkedHashMap<>();
        for (UnsafeMapper mapper : unsafeMethods) {
            unsafeByInterface
                    .computeIfAbsent(mapper.interfaceName(), k -> new LinkedHashSet<>())
                    .add(mapper.methodName());
            lookupMap.put(
                    mapper.interfaceName() + "#" + mapper.methodName(),
                    mapper
            );
        }

        List<Sink> sinks = new ArrayList<>();
        int seq = 0;
        for (MethodNode method : index.methods()) {
            for (CallSite call : method.calls()) {
                String receiverType = call.receiverType();
                Set<String> methods = unsafeByInterface.get(receiverType);
                if (methods == null) {
                    methods = unsafeByInterface.get(
                            AnalysisTextUtils.simpleName(receiverType)
                    );
                }
                if (methods != null && methods.contains(call.methodName())) {
                    UnsafeMapper mapper = lookupMap.getOrDefault(
                            receiverType + "#" + call.methodName(),
                            lookupMap.get(
                                    AnalysisTextUtils.simpleName(receiverType)
                                            + "#" + call.methodName()
                            )
                    );
                    String api = "MyBatis ${}:" + call.expression();
                    sinks.add(new Sink(
                            "mybatis-sink-" + (++seq),
                            "SQL_EXECUTION",
                            api,
                            method.id(),
                            method.filePath(),
                            call.line(),
                            mapper != null ? mapper.snippet() : call.expression()
                    ));
                }
            }
        }
        return sinks;
    }
}
