package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.agentscope.core.event.ExceedMaxItersEvent;
import io.agentscope.core.event.TextBlockDeltaEvent;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class AgentScopeEventCollectorTest {

    @Test
    void keepsSupervisorAndSubagentTextInSeparateLogsAndResult() {
        List<String> logs = new ArrayList<>();
        AgentScopeEventCollector collector = new AgentScopeEventCollector(
                logs::add
        );

        collector.handle(new TextBlockDeltaEvent("r1", "b1", "Final {")
                .withSource("audit-supervisor"));
        collector.handle(new TextBlockDeltaEvent("r2", "b2", "hunter detail.")
                .withSource("ssrf"));
        collector.handle(new TextBlockDeltaEvent("r1", "b1", "\"findings\":[]}")
                .withSource("audit-supervisor"));
        collector.flushAll();

        assertThat(logs).containsExactly(
                "[agentscope-ssrf] hunter detail.",
                "[agentscope-supervisor] Final {\"findings\":[]}"
        );
        assertThat(collector.finalResult())
                .isEqualTo("Final {\"findings\":[]}");
    }

    @Test
    void subagentMaxIterationsIsLoggedWithoutFailingSupervisor() {
        List<String> logs = new ArrayList<>();
        AgentScopeEventCollector collector = new AgentScopeEventCollector(
                logs::add
        );

        collector.handle(new ExceedMaxItersEvent("r1", 30, 30)
                .withSource("ssrf"));

        assertThat(logs).containsExactly(
                "[agentscope-ssrf] AgentScope exceeded max iterations: 30/30"
        );
    }

    @Test
    void supervisorMaxIterationsStillFailsAudit() {
        AgentScopeEventCollector collector = new AgentScopeEventCollector(
                ignored -> {
                }
        );

        assertThatThrownBy(() -> collector.handle(
                new ExceedMaxItersEvent("r1", 80, 80)
                        .withSource("audit-supervisor")
        ))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("AgentScope exceeded max iterations: 80/80");
    }
}
