package com.huawei.audit.analysis.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.analysis.impl.DangerousSinkClassifier.ExtraSinkRule;
import com.huawei.audit.process.ProcessRunner;
import com.huawei.audit.process.ProcessResult;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

final class LlmSinkExpander {
    private static final List<String> KNOWN_CATEGORIES = List.of(
            "COMMAND_EXECUTION", "SCRIPT_OR_EXPRESSION_EXECUTION",
            "NATIVE_DESERIALIZATION", "DYNAMIC_LOADING", "SQL_EXECUTION",
            "XML_PARSE", "HTTP_RESPONSE_WRITE", "HTTP_HEADER_WRITE",
            "HTTP_REDIRECT", "JNDI_LOOKUP", "FILE_WRITE",
            "OUTBOUND_HTTP", "NATIVE_LIBRARY"
    );
    private static final Pattern FENCED_JSON = Pattern.compile(
            "```(?:json)?\\s*([\\s\\S]*?)\\s*```",
            Pattern.CASE_INSENSITIVE
    );

    private final ObjectMapper objectMapper = new ObjectMapper();

    List<ExtraSinkRule> expand(
            List<Map<String, String>> dependencies,
            ProcessRunner processRunner,
            String claudeBin,
            Path workingDirectory
    ) {
        if (dependencies == null || dependencies.isEmpty()
                || processRunner == null || claudeBin == null) {
            return List.of();
        }
        try {
            String depText = dependencies.stream()
                    .map(dep -> dep.getOrDefault("groupId", "")
                            + ":" + dep.getOrDefault("artifactId", ""))
                    .filter(s -> !s.equals(":"))
                    .distinct()
                    .limit(200)
                    .collect(Collectors.joining("\n"));
            if (depText.isBlank()) {
                return List.of();
            }
            String categories = String.join(", ", KNOWN_CATEGORIES);
            String prompt = PROMPT_TEMPLATE.formatted(depText, categories);
            List<String> command = List.of(
                    claudeBin, "--print", "--output-format", "json", "-p", prompt
            );
            ProcessResult result = processRunner.run(
                    command, workingDirectory, Map.of(),
                    Duration.ofSeconds(60), null, line -> {}
            );
            if (result.exitCode() != 0) {
                return List.of();
            }
            return parseRules(String.join("\n", result.output()));
        } catch (Exception ignored) {
            return List.of();
        }
    }

    private List<ExtraSinkRule> parseRules(String rawOutput) {
        try {
            String jsonArray = extractJsonArray(rawOutput);
            if (jsonArray == null) {
                return List.of();
            }
            List<Map<String, String>> items = objectMapper.readValue(
                    jsonArray, new TypeReference<>() {}
            );
            List<ExtraSinkRule> rules = new ArrayList<>();
            for (Map<String, String> item : items) {
                String methodName = item.getOrDefault("methodName", "").strip();
                String receiverType = item.getOrDefault("receiverType", "").strip()
                        .toLowerCase(Locale.ROOT);
                String category = item.getOrDefault("category", "").strip();
                if (methodName.isEmpty() || receiverType.isEmpty()
                        || !KNOWN_CATEGORIES.contains(category)) {
                    continue;
                }
                rules.add(new ExtraSinkRule(methodName, receiverType, category));
            }
            return List.copyOf(rules);
        } catch (Exception ignored) {
            return List.of();
        }
    }

    String extractJsonArray(String rawOutput) {
        if (rawOutput == null) {
            return null;
        }
        try {
            JsonNode root = objectMapper.readTree(rawOutput.strip());
            if (root.isObject() && root.has("result")) {
                rawOutput = root.get("result").asText();
            }
        } catch (Exception ignored) {
        }
        Matcher fenced = FENCED_JSON.matcher(rawOutput);
        while (fenced.find()) {
            String body = fenced.group(1).strip();
            if (body.startsWith("[")) {
                return body;
            }
        }
        int start = rawOutput.indexOf('[');
        int end = rawOutput.lastIndexOf(']');
        if (start >= 0 && end > start) {
            return rawOutput.substring(start, end + 1);
        }
        return null;
    }

    private static final String PROMPT_TEMPLATE = """
            你是一个 Java 安全审计专家。下面是一个 Java 项目的依赖列表：\s

            %s

            已有的内置 sink 识别覆盖了标准库和主流框架（如 Runtime.exec、ProcessBuilder、
            ObjectInputStream.readObject、JdbcTemplate、DocumentBuilder.parse、
            SpEL/OGNL/Groovy/Freemarker/Velocity 表达式引擎等）。

            请分析上述依赖，找出其中可能包含但**未被内置规则覆盖**的危险 sink 方法。
            重点关注：
            - 冷门或企业内部 ORM/数据库框架的 SQL 执行方法
            - 非标准 HTTP 客户端的请求发送方法
            - 非标准序列化/反序列化库的解析方法
            - 脚本/表达式引擎的执行方法
            - 文件操作封装库的写入方法

            只输出 JSON 数组，不要任何解释文字。每个元素格式：
            {"methodName": "方法名（精确）", "receiverType": "接收者类型关键字（小写，用于包含匹配）", "category": "类别"}

            可用 category 值：%s

            如果没有需要补充的 sink，输出空数组 []。
            """;
}
