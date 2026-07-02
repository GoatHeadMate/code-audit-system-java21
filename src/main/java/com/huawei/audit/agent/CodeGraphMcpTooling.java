package com.huawei.audit.agent;

import com.huawei.audit.config.CodeGraphProperties;
import io.agentscope.harness.agent.tools.McpServerConfig;
import io.agentscope.harness.agent.tools.ToolsConfig;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
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
        server.setTimeout(properties.timeout());
        server.setInitializationTimeout(properties.initializationTimeout());

        ToolsConfig config = new ToolsConfig();
        config.setMcpServers(Map.of(SERVER_NAME, server));
        return Optional.of(config);
    }

    private Map<String, String> mcpEnv() {
        Map<String, String> env = new LinkedHashMap<>();
        env.put("CODEGRAPH_MCP_TOOLS", properties.mcpToolsEnvValue());
        return env;
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
            Process process = new ProcessBuilder(
                    effectiveCommand(),
                    "init",
                    project.toString()
            ).redirectErrorStream(true)
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .start();
            boolean finished = process.waitFor(
                    properties.initTimeout().toMillis(),
                    TimeUnit.MILLISECONDS
            );
            if (!finished) {
                process.destroyForcibly();
                publish(eventConsumer, "[codegraph] init timed out after "
                        + format(properties.initTimeout()) + "; continuing without indexed MCP tools");
                return false;
            }
            if (process.exitValue() != 0) {
                publish(eventConsumer, "[codegraph] init failed with exit code "
                        + process.exitValue() + "; continuing without indexed MCP tools");
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

    private static String format(Duration duration) {
        return duration == null ? "" : duration.toString();
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
