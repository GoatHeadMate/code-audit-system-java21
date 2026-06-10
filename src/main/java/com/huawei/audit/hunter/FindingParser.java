package com.huawei.audit.hunter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class FindingParser {
    private static final Pattern FENCED_JSON = Pattern.compile(
            "```(?:json)?\\s*(\\[[\\s\\S]*?])\\s*```",
            Pattern.CASE_INSENSITIVE
    );

    private final ObjectMapper objectMapper;

    public FindingParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public List<Map<String, Object>> parse(String text, String hunter) {
        JsonNode array = findArray(text);
        if (array == null) {
            return List.of();
        }

        List<Map<String, Object>> raw = objectMapper.convertValue(
                array,
                new TypeReference<>() { }
        );
        List<Map<String, Object>> normalized = new ArrayList<>();
        for (Map<String, Object> item : raw) {
            Map<String, Object> finding = new LinkedHashMap<>(item);
            String filePath = stringValue(finding, "file_path", "file");
            int startLine = intValue(finding, "start_line", "line");
            String vulnType = stringValue(
                    finding,
                    "vuln_type",
                    "vulnerability_type"
            );
            if (vulnType.isBlank()) {
                vulnType = hunter;
            }

            finding.put("file_path", filePath);
            finding.put("start_line", startLine);
            finding.put("message", stringValue(
                    finding,
                    "message",
                    "description",
                    "title"
            ));
            finding.put("vuln_type", vulnType.toUpperCase(Locale.ROOT));
            finding.put("vulnerability_type", vulnType.toUpperCase(Locale.ROOT));
            finding.putIfAbsent("discovered_by", hunter);
            finding.putIfAbsent("data_flow_path", List.of());
            normalized.add(finding);
        }
        return normalized;
    }

    private JsonNode findArray(String text) {
        String stripped = text == null ? "" : text.strip();
        JsonNode direct = parseArray(stripped);
        if (direct != null) {
            return direct;
        }

        Matcher matcher = FENCED_JSON.matcher(stripped);
        JsonNode fenced = null;
        while (matcher.find()) {
            JsonNode candidate = parseArray(matcher.group(1));
            if (candidate != null) {
                fenced = candidate;
            }
        }
        if (fenced != null) {
            return fenced;
        }

        JsonNode last = null;
        for (int index = stripped.indexOf('[');
             index >= 0;
             index = stripped.indexOf('[', index + 1)) {
            JsonNode candidate = parseArray(stripped.substring(index));
            if (candidate != null) {
                last = candidate;
            }
        }
        return last;
    }

    private JsonNode parseArray(String candidate) {
        try {
            JsonNode node = objectMapper.readTree(candidate);
            return node != null && node.isArray() ? node : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private String stringValue(Map<String, Object> finding, String... keys) {
        for (String key : keys) {
            Object value = finding.get(key);
            if (value != null && !value.toString().isBlank()) {
                return value.toString();
            }
        }
        return "";
    }

    private int intValue(Map<String, Object> finding, String... keys) {
        for (String key : keys) {
            Object value = finding.get(key);
            if (value instanceof Number number) {
                return number.intValue();
            }
            if (value != null) {
                try {
                    return Integer.parseInt(value.toString());
                } catch (NumberFormatException ignored) {
                    // Try the next compatible field.
                }
            }
        }
        return 0;
    }
}
