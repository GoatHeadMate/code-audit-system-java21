package com.huawei.audit.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Component;

@Component
public class RuntimeExecutables {
    private final String codeql;
    private final String claude;

    public RuntimeExecutables(AuditProperties properties) {
        this.codeql = resolveCodeql(properties.codeqlBin());
        this.claude = resolveClaude(properties.claudeBin());
    }

    public String codeql() {
        return codeql;
    }

    public String claude() {
        return claude;
    }

    public boolean codeqlAvailable() {
        return executableExists(codeql);
    }

    public boolean claudeAvailable() {
        return executableExists(claude);
    }

    private String resolveCodeql(String configured) {
        String resolved = resolveOnPath(configured);
        if (!resolved.equals(configured) || !isBareCommand(configured)) {
            return resolved;
        }

        Path project = Path.of("").toAbsolutePath().normalize();
        Path parent = project.getParent();
        if (parent != null) {
            Path sibling = parent.resolve("codeql").resolve("codeql").resolve("codeql.exe");
            if (Files.isRegularFile(sibling)) {
                return sibling.toString();
            }
        }
        return configured;
    }

    private String resolveClaude(String configured) {
        String resolved = resolveOnPath(configured);
        if (!resolved.equals(configured) || !isBareCommand(configured)) {
            return resolved;
        }

        String localAppData = System.getenv("LOCALAPPDATA");
        if (localAppData == null || localAppData.isBlank()) {
            return configured;
        }
        Path packages = Path.of(localAppData, "Microsoft", "WinGet", "Packages");
        if (!Files.isDirectory(packages)) {
            return configured;
        }

        try (var directories = Files.list(packages)) {
            return directories
                    .filter(Files::isDirectory)
                    .filter(path -> path.getFileName().toString()
                            .startsWith("Anthropic.ClaudeCode_"))
                    .map(path -> path.resolve("claude.exe"))
                    .filter(Files::isRegularFile)
                    .map(path -> path.toAbsolutePath().normalize().toString())
                    .findFirst()
                    .orElse(configured);
        } catch (IOException | SecurityException ignored) {
            return configured;
        }
    }

    private String resolveOnPath(String configured) {
        Path configuredPath = Path.of(configured);
        if (!isBareCommand(configured) && Files.isRegularFile(configuredPath)) {
            return configuredPath.toAbsolutePath().normalize().toString();
        }

        String pathValue = System.getenv("PATH");
        if (pathValue == null || pathValue.isBlank()) {
            return configured;
        }

        for (String directory : pathValue.split(java.io.File.pathSeparator)) {
            for (String candidate : candidates(configured)) {
                try {
                    Path path = Path.of(directory, candidate);
                    if (Files.isRegularFile(path)) {
                        return path.toAbsolutePath().normalize().toString();
                    }
                } catch (RuntimeException ignored) {
                    // Ignore malformed or inaccessible PATH entries.
                }
            }
        }
        return configured;
    }

    private List<String> candidates(String command) {
        List<String> candidates = new ArrayList<>();
        if (System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win")
                && !command.contains(".")) {
            // On Windows, prefer .exe/.cmd over the bare name (which may be a Unix shell script).
            candidates.add(command + ".exe");
            candidates.add(command + ".cmd");
        }
        candidates.add(command);
        return candidates;
    }

    private boolean isBareCommand(String command) {
        return !command.contains("/") && !command.contains("\\");
    }

    private boolean executableExists(String executable) {
        return !isBareCommand(executable) && Files.isRegularFile(Path.of(executable));
    }
}
