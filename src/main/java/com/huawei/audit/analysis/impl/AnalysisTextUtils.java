package com.huawei.audit.analysis.impl;

import java.nio.file.Path;

final class AnalysisTextUtils {
    private AnalysisTextUtils() {
    }

    static String relativePath(Path root, Path file) {
        try {
            return root.toAbsolutePath().normalize()
                    .relativize(file.toAbsolutePath().normalize())
                    .toString()
                    .replace('\\', '/');
        } catch (Exception ignored) {
            return file.toString().replace('\\', '/');
        }
    }

    static boolean startsUppercase(String value) {
        return value != null
                && !value.isBlank()
                && Character.isUpperCase(value.charAt(0));
    }

    static String simpleName(String type) {
        if (type == null) {
            return "";
        }
        String cleaned = type
                .replaceAll("<.*>", "")
                .replace("[]", "")
                .strip();
        int separator = Math.max(
                cleaned.lastIndexOf('.'),
                cleaned.lastIndexOf('$')
        );
        return separator >= 0 ? cleaned.substring(separator + 1) : cleaned;
    }
}
