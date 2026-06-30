package com.huawei.audit.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import org.junit.jupiter.api.Test;

class AgentScopePropertiesTest {

    @Test
    void defaultsIdleTimeoutWhenMissingOrInvalid() {
        AgentScopeProperties missing = new AgentScopeProperties(
                "anthropic",
                "glm-5.2",
                "",
                "",
                80,
                Duration.ofMinutes(30),
                null
        );
        AgentScopeProperties invalid = new AgentScopeProperties(
                "anthropic",
                "glm-5.2",
                "",
                "",
                80,
                Duration.ofMinutes(30),
                Duration.ZERO
        );

        assertThat(missing.idleTimeout()).isEqualTo(Duration.ofMinutes(5));
        assertThat(invalid.idleTimeout()).isEqualTo(Duration.ofMinutes(5));
    }

    @Test
    void keepsConfiguredIdleTimeout() {
        AgentScopeProperties properties = new AgentScopeProperties(
                "anthropic",
                "glm-5.2",
                "",
                "",
                80,
                Duration.ofMinutes(30),
                Duration.ofMinutes(2)
        );

        assertThat(properties.idleTimeout()).isEqualTo(Duration.ofMinutes(2));
    }
}
