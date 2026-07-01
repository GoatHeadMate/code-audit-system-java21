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
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.springframework.stereotype.Component;

@Component
public class CodeGraphMcpTooling {
    private static final String SERVER_NAME = "codegraph";

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
        if (properties.autoIndex()) {
            ensureIndex(project, eventConsumer);
        }
        McpServerConfig server = new McpServerConfig();
        server.setTransport("stdio");
        server.setCommand(properties.command());
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

    private void ensureIndex(Path project, Consumer<String> eventConsumer) {
        if (Files.isDirectory(project.resolve(".codegraph"))) {
            return;
        }
        if (!Files.isDirectory(project)) {
            publish(eventConsumer, "[codegraph] source root is not a directory; MCP disabled for this session");
            return;
        }
        publish(eventConsumer, "[codegraph] initializing CodeGraph index for MCP tools");
        try {
            Process process = new ProcessBuilder(
                    properties.command(),
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
                return;
            }
            if (process.exitValue() != 0) {
                publish(eventConsumer, "[codegraph] init failed with exit code "
                        + process.exitValue() + "; continuing without indexed MCP tools");
                return;
            }
            publish(eventConsumer, "[codegraph] index ready for MCP tools");
        } catch (IOException exception) {
            publish(eventConsumer, "[codegraph] init could not start: "
                    + exception.getMessage() + "; continuing without indexed MCP tools");
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            publish(eventConsumer, "[codegraph] init interrupted; continuing without indexed MCP tools");
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
}
