package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.config.AgentScopeProperties;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.time.Duration;
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
}
