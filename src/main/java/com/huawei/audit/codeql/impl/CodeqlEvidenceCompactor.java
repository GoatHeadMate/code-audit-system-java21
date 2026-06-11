package com.huawei.audit.codeql.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

final class CodeqlEvidenceCompactor {
    private final ObjectMapper objectMapper;

    CodeqlEvidenceCompactor(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    JsonNode compact(JsonNode node, int maxChars) throws Exception {
        if (objectMapper.writeValueAsString(node).length() <= maxChars
                || !node.isObject()) {
            return node;
        }

        ObjectNode compact = objectMapper.createObjectNode();
        node.fields().forEachRemaining(entry -> {
            JsonNode value = entry.getValue();
            if (!value.isObject() || !value.has("tuples")) {
                compact.set(entry.getKey(), value);
                return;
            }

            ObjectNode table = objectMapper.createObjectNode();
            if (value.has("columns")) {
                table.set("columns", value.get("columns"));
            }
            ArrayNode tuples = objectMapper.createArrayNode();
            table.set("tuples", tuples);
            compact.set(entry.getKey(), table);

            JsonNode sourceRows = value.get("tuples");
            int totalRows = sourceRows.isArray() ? sourceRows.size() : 0;
            for (JsonNode row : sourceRows) {
                tuples.add(row);
                if (exceedsLimit(compact, maxChars)) {
                    tuples.remove(tuples.size() - 1);
                    break;
                }
            }
            table.put("total_rows", totalRows);
            table.put("truncated", tuples.size() < totalRows);
        });
        return compact;
    }

    private boolean exceedsLimit(ObjectNode node, int maxChars) {
        try {
            return objectMapper.writeValueAsString(node).length() > maxChars;
        } catch (Exception exception) {
            return true;
        }
    }
}
