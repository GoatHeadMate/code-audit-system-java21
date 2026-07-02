package com.huawei.audit.agent;

import com.huawei.audit.config.CodeGraphProperties;
import io.agentscope.harness.agent.tools.McpServerConfig;
import io.agentscope.harness.agent.tools.ToolsConfig;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import org.springframework.stereotype.Component;

@Component
public class CodeGraphMcpTooling {
    private static final String SERVER_NAME = "codegraph";
    private static final ConcurrentHashMap<Path, Object> INIT_LOCKS =
            new ConcurrentHashMap<>();
    private static final ConcurrentHashMap.KeySetView<Path, Boolean> INIT_FAILURES =
            ConcurrentHashMap.newKeySet();

    private final CodeGraphProperties properties;

    public CodeGraphMcpTooling(CodeGraphProperties properties) {
        this.properties = properties;
    }

    public static CodeGraphMcpTooling disabled() {
        return new CodeGraphMcpTooling(CodeGraphProperties.disabled());
    }

    public boolean enabled() {
        return properties.enabled();
    }

    public List<String> toolNames() {
        return enabled() ? properties.tools() : List.of();
    }

    public Optional<ToolsConfig> toolsConfig(
            Path sourceRoot,
            Consumer<String> eventConsumer
    ) {
        if (!enabled() || sourceRoot == null) {
            return Optional.empty();
        }
        Path project = sourceRoot.toAbsolutePath().normalize();
        if (properties.autoIndex() && !ensureIndex(project, eventConsumer)) {
            return Optional.empty();
        }
        McpServerConfig server = new McpServerConfig();
        server.setTransport("stdio");
        server.setCommand(effectiveCommand());
        server.setArgs(List.of(
                "serve",
                "--mcp",
                "--path",
                project.toString()
        ));
        server.setEnv(mcpEnv());
        server.setEnableTools(properties.tools());

        ToolsConfig config = new ToolsConfig();
        config.setMcpServers(Map.of(SERVER_NAME, server));
        return Optional.of(config);
    }

    private Map<String, String> mcpEnv() {
        Map<String, String> env = new LinkedHashMap<>();
        env.put("CODEGRAPH_MCP_TOOLS", properties.mcpToolsEnvValue());
        if (properties.hasNodeHome()) {
            env.put("PATH", prependNodeHome(System.getenv("PATH")));
        }
        return env;
    }

    private String prependNodeHome(String inheritedPath) {
        String base = inheritedPath == null ? "" : inheritedPath;
        return base.isEmpty()
                ? properties.nodeHome()
                : properties.nodeHome() + File.pathSeparator + base;
    }

    private boolean ensureIndex(Path project, Consumer<String> eventConsumer) {
        Path lockKey = project.toAbsolutePath().normalize();
        if (Files.isDirectory(project.resolve(".codegraph"))) {
            INIT_FAILURES.remove(lockKey);
            return true;
        }
        if (INIT_FAILURES.contains(lockKey)) {
            publish(eventConsumer, "[codegraph] index initialization already failed for this project; "
                    + "continuing without indexed MCP tools");
            return false;
        }
        Object lock = INIT_LOCKS.computeIfAbsent(lockKey, ignored -> new Object());
        synchronized (lock) {
            try {
                if (Files.isDirectory(project.resolve(".codegraph"))) {
                    INIT_FAILURES.remove(lockKey);
                    return true;
                }
                if (INIT_FAILURES.contains(lockKey)) {
                    publish(eventConsumer, "[codegraph] index initialization already failed for this project; "
                            + "continuing without indexed MCP tools");
                    return false;
                }
                boolean indexed = ensureIndexLocked(project, eventConsumer);
                if (indexed) {
                    INIT_FAILURES.remove(lockKey);
                } else {
                    INIT_FAILURES.add(lockKey);
                }
                return indexed;
            } finally {
                INIT_LOCKS.remove(lockKey, lock);
            }
        }
    }

    private boolean ensureIndexLocked(Path project, Consumer<String> eventConsumer) {
        if (Files.isDirectory(project.resolve(".codegraph"))) {
            return true;
        }
        if (!Files.isDirectory(project)) {
            publish(eventConsumer, "[codegraph] source root is not a directory; MCP disabled for this session");
            return false;
        }
        publish(eventConsumer, "[codegraph] initializing CodeGraph index for MCP tools");
        try {
            ProcessBuilder builder = new ProcessBuilder(
                    effectiveCommand(),
                    "init",
                    project.toString()
            ).redirectErrorStream(true);
            if (properties.hasNodeHome()) {
                builder.environment().put(
                        "PATH", prependNodeHome(builder.environment().get("PATH")));
            }
            Process process = builder.start();
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            Thread outputReader = Thread.ofVirtual().start(() -> copyOutput(process, output));
            process.waitFor();
            waitForOutput(outputReader);
            if (process.exitValue() != 0) {
                publish(eventConsumer, "[codegraph] init failed with exit code "
                        + process.exitValue() + formatOutput(output)
                        + "; continuing without indexed MCP tools");
                return false;
            }
            publish(eventConsumer, "[codegraph] index ready for MCP tools");
            return true;
        } catch (IOException exception) {
            publish(eventConsumer, "[codegraph] init could not start: "
                    + exception.getMessage() + "; continuing without indexed MCP tools");
            return false;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            publish(eventConsumer, "[codegraph] init interrupted; continuing without indexed MCP tools");
            return false;
        }
    }

    private static void publish(Consumer<String> consumer, String message) {
        if (consumer != null) {
            consumer.accept(message);
        }
    }

    private static void copyOutput(Process process, ByteArrayOutputStream output) {
        try {
            process.getInputStream().transferTo(output);
        } catch (IOException ignored) {
        }
    }

    private static void waitForOutput(Thread outputReader) {
        try {
            outputReader.join(1_000);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static String formatOutput(ByteArrayOutputStream output) {
        String text = output.toString(StandardCharsets.UTF_8)
                .replaceAll("\\u001B\\[[;\\d]*[ -/]*[@-~]", "")
                .replace('\r', ' ')
                .replace('\n', ' ')
                .replaceAll("\\s+", " ")
                .trim();
        if (text.isEmpty()) {
            return "";
        }
        int maxLength = 800;
        String summary = text.length() <= maxLength
                ? text
                : text.substring(0, maxLength) + "...";
        return "; output: " + summary;
    }

    String effectiveCommand() {
        if (isWindows() && "codegraph".equalsIgnoreCase(properties.command())) {
            return "codegraph.cmd";
        }
        return properties.command();
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "")
                .toLowerCase()
                .contains("win");
    }
}
