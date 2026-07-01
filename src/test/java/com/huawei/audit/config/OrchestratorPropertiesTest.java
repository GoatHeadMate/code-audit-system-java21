package com.huawei.audit.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import org.junit.jupiter.api.Test;

class OrchestratorPropertiesTest {

    @Test
    void defaultsAuditBudgetControlsWhenMissingOrInvalid() {
        OrchestratorProperties properties = new OrchestratorProperties(
                true, 10, 5, 80,
                0, 0, Duration.ZERO,
                0, Duration.ZERO, Duration.ZERO
        );

        assertThat(properties.maxHunterSessionsPerRound()).isEqualTo(24);
        assertThat(properties.maxRounds()).isEqualTo(5);
        assertThat(properties.maxTotalJobDuration()).isEqualTo(Duration.ofHours(6));
        assertThat(properties.maxParallelHunterSessions()).isEqualTo(2);
        assertThat(properties.hunterSessionTimeout()).isEqualTo(Duration.ofMinutes(12));
        assertThat(properties.modelSlotTimeout()).isEqualTo(Duration.ofMinutes(2));
    }

    @Test
    void clampsAuditBudgetControlsToOperationalBounds() {
        OrchestratorProperties properties = new OrchestratorProperties(
                true, 10, 5, 80,
                200, 100, Duration.ofDays(3),
                200, Duration.ofHours(3), Duration.ofMinutes(45)
        );

        assertThat(properties.maxHunterSessionsPerRound()).isEqualTo(100);
        assertThat(properties.maxRounds()).isEqualTo(50);
        assertThat(properties.maxTotalJobDuration()).isEqualTo(Duration.ofHours(24));
        assertThat(properties.maxParallelHunterSessions()).isEqualTo(20);
        assertThat(properties.hunterSessionTimeout()).isEqualTo(Duration.ofHours(2));
        assertThat(properties.modelSlotTimeout()).isEqualTo(Duration.ofMinutes(30));
    }
}
