package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.config.AgentScopeProperties;
import com.huawei.audit.config.CodeGraphProperties;
import io.agentscope.harness.agent.tools.ToolsConfig;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AgentScopeGatewayTest {

    @TempDir
    Path tempDir;

    @Test
    void disablesAgentScopeTraceMiddlewareLogs() throws Exception {
        AgentScopeGateway gateway = new AgentScopeGateway(new AgentScopeProperties(
                "anthropic",
                "test-model",
                "test-key",
                "",
                80,
                Duration.ofSeconds(1),
                Duration.ofSeconds(1)
        ));

        Method baseBuilder = AgentScopeGateway.class.getDeclaredMethod(
                "baseBuilder",
                Path.class,
                Path.class,
                List.class
        );
        baseBuilder.setAccessible(true);
        Object builder = baseBuilder.invoke(gateway, tempDir, tempDir, List.of());

        Field tracing = builder.getClass().getDeclaredField("agentTracingLogEnabled");
        tracing.setAccessible(true);
        assertThat(tracing.getBoolean(builder)).isFalse();
    }

    @Test
    void buildsCodeGraphStdioMcpToolsConfig() {
        CodeGraphMcpTooling tooling = new CodeGraphMcpTooling(new CodeGraphProperties(
                true,
                "codegraph",
                List.of("codegraph_explore"),
                false,
                Duration.ofSeconds(2),
                Duration.ofSeconds(3),
                Duration.ofSeconds(4),
                ""
        ));

        ToolsConfig config = tooling.toolsConfig(tempDir, ignored -> {
        }).orElseThrow();

        var server = config.getMcpServers().get("codegraph");
        assertThat(server.getTransport()).isEqualTo("stdio");
        assertThat(server.getCommand()).isEqualTo(defaultCodeGraphCommand());
        assertThat(server.getArgs()).containsExactly(
                "serve",
                "--mcp",
                "--path",
                tempDir.toAbsolutePath().normalize().toString()
        );
        assertThat(server.getEnableTools()).containsExactly("codegraph_explore");
        assertThat(server.getEnv()).containsEntry("CODEGRAPH_MCP_TOOLS", "explore");
    }

    @Test
    void preservesExplicitCodeGraphCommand() {
        CodeGraphMcpTooling tooling = new CodeGraphMcpTooling(new CodeGraphProperties(
                true,
                "D:\\tools\\codegraph.cmd",
                List.of("codegraph_explore"),
                false,
                Duration.ofSeconds(2),
                Duration.ofSeconds(3),
                Duration.ofSeconds(4),
                ""
        ));

        ToolsConfig config = tooling.toolsConfig(tempDir, ignored -> {
        }).orElseThrow();

        var server = config.getMcpServers().get("codegraph");
        assertThat(server.getCommand()).isEqualTo("D:\\tools\\codegraph.cmd");
    }

    @Test
    void skipsMcpConfigWhenAutoIndexCommandCannotStart() {
        CodeGraphMcpTooling tooling = new CodeGraphMcpTooling(new CodeGraphProperties(
                true,
                "missing-codegraph-command-for-test",
                List.of("codegraph_explore"),
                true,
                Duration.ofSeconds(2),
                Duration.ofSeconds(3),
                Duration.ofSeconds(4),
                ""
        ));
        List<String> events = new ArrayList<>();

        assertThat(tooling.toolsConfig(tempDir, events::add)).isEmpty();
        assertThat(tooling.toolsConfig(tempDir, events::add)).isEmpty();
        assertThat(events)
                .anySatisfy(event -> assertThat(event).contains("init could not start"))
                .anySatisfy(event -> assertThat(event).contains("already failed"));
    }

    @Test
    void prependsConfiguredNodeHomeToMcpServerPathWhenSet() {
        CodeGraphMcpTooling tooling = new CodeGraphMcpTooling(new CodeGraphProperties(
                true,
                "codegraph",
                List.of("codegraph_explore"),
                false,
                Duration.ofSeconds(2),
                Duration.ofSeconds(3),
                Duration.ofSeconds(4),
                "D:\\huawei\\tools\\node-v22.23.1-win-x64"
        ));

        ToolsConfig config = tooling.toolsConfig(tempDir, ignored -> {
        }).orElseThrow();

        var server = config.getMcpServers().get("codegraph");
        assertThat(server.getEnv().get("PATH"))
                .startsWith("D:\\huawei\\tools\\node-v22.23.1-win-x64" + File.pathSeparator);
    }

    @Test
    void leavesPathUntouchedWhenNodeHomeNotConfigured() {
        CodeGraphMcpTooling tooling = new CodeGraphMcpTooling(new CodeGraphProperties(
                true,
                "codegraph",
                List.of("codegraph_explore"),
                false,
                Duration.ofSeconds(2),
                Duration.ofSeconds(3),
                Duration.ofSeconds(4),
                ""
        ));

        ToolsConfig config = tooling.toolsConfig(tempDir, ignored -> {
        }).orElseThrow();

        var server = config.getMcpServers().get("codegraph");
        assertThat(server.getEnv()).doesNotContainKey("PATH");
    }

    private static String defaultCodeGraphCommand() {
        return System.getProperty("os.name", "")
                        .toLowerCase()
                        .contains("win")
                ? "codegraph.cmd"
                : "codegraph";
    }
}
