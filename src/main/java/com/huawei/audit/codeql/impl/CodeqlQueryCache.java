package com.huawei.audit.codeql.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.HexFormat;

final class CodeqlQueryCache {
    private final ObjectMapper objectMapper;
    private final Path queryRoot;

    CodeqlQueryCache(ObjectMapper objectMapper, Path queryRoot) {
        this.objectMapper = objectMapper;
        this.queryRoot = queryRoot;
    }

    Path cacheFile(Path database, String hunter, Path query) throws Exception {
        return database.getParent()
                .resolve("query_cache")
                .resolve(hunter)
                .resolve(
                        query.getFileName() + "-"
                                + queryFingerprint(query) + ".json"
                );
    }

    JsonNode read(Path cacheFile) {
        if (!Files.isRegularFile(cacheFile)) {
            return null;
        }
        try {
            return objectMapper.readTree(cacheFile.toFile());
        } catch (Exception exception) {
            return null;
        }
    }

    void write(Path cacheFile, JsonNode node) throws IOException {
        Files.createDirectories(cacheFile.getParent());
        Path temporary = Files.createTempFile(
                cacheFile.getParent(),
                cacheFile.getFileName().toString(),
                ".tmp"
        );
        objectMapper.writeValue(temporary.toFile(), node);
        try {
            Files.move(
                    temporary,
                    cacheFile,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING
            );
        } catch (IOException exception) {
            Files.move(
                    temporary,
                    cacheFile,
                    StandardCopyOption.REPLACE_EXISTING
            );
        }
    }

    private String queryFingerprint(Path query) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        updateDigest(digest, query);
        updateDigest(digest, queryRoot.resolve("qlpack.yml"));
        updateDigest(digest, queryRoot.resolve("codeql-pack.lock.yml"));

        Path sinks = queryRoot.resolve("sinks");
        if (Files.isDirectory(sinks)) {
            try (var files = Files.list(sinks)) {
                for (Path file : files
                        .filter(Files::isRegularFile)
                        .sorted()
                        .toList()) {
                    updateDigest(digest, file);
                }
            }
        }
        return HexFormat.of().formatHex(digest.digest(), 0, 12);
    }

    private void updateDigest(MessageDigest digest, Path file)
            throws IOException {
        if (Files.isRegularFile(file)) {
            digest.update(Files.readAllBytes(file));
        }
    }
}
