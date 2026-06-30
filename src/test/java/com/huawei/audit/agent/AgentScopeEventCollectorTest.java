package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.agentscope.core.event.ExceedMaxItersEvent;
import io.agentscope.core.event.TextBlockDeltaEvent;
import io.agentscope.core.event.ToolCallStartEvent;
import io.agentscope.core.event.ToolResultEndEvent;
import io.agentscope.core.message.ToolResultState;
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

        collector.handle(new TextBlockDeltaEvent("r1", "b1", "{")
                .withSource("audit-supervisor"));
        collector.handle(new TextBlockDeltaEvent("r2", "b2", "hunter detail.")
                .withSource("ssrf"));
        collector.handle(new TextBlockDeltaEvent(
                "r1",
                "b1",
                "\"selected_hunters\":[],\"findings\":[]}"
        )
                .withSource("audit-supervisor"));
        collector.flushAll();

        assertThat(logs).containsExactly(
                "[agentscope-ssrf] hunter detail.",
                "[agentscope-supervisor] {\"selected_hunters\":[],\"findings\":[]}"
        );
        assertThat(collector.finalResult())
                .isEqualTo("{\"selected_hunters\":[],\"findings\":[]}");
    }

    @Test
    void planningTextIsNotAcceptedAsFinalResult() {
        AgentScopeEventCollector collector = new AgentScopeEventCollector(
                ignored -> {
                }
        );

        collector.handle(new TextBlockDeltaEvent(
                "r1",
                "b1",
                "I'll start by examining the project structure."
        ).withSource("audit-supervisor"));
        collector.flushAll();

        assertThat(collector.finalResult()).isBlank();
    }

    @Test
    void tracksStartedAndCompletedSupervisorAgentSpawns() {
        AgentScopeEventCollector collector = new AgentScopeEventCollector(
                ignored -> {
                }
        );

        collector.handle(new ToolCallStartEvent("r1", "call-1", "agent_spawn")
                .withSource("audit-supervisor"));
        collector.handle(new ToolCallStartEvent("r1", "call-2", "agent_spawn")
                .withSource("audit-supervisor"));
        collector.handle(new ToolResultEndEvent(
                "r1",
                "call-1",
                "agent_spawn",
                ToolResultState.SUCCESS
        ).withSource("audit-supervisor"));

        assertThat(collector.startedAgentSpawns()).isEqualTo(2);
        assertThat(collector.completedAgentSpawns()).isEqualTo(1);
        assertThat(collector.finalResult()).isBlank();
    }

    @Test
    void logsSubagentToolStartAndEndEvents() {
        List<String> logs = new ArrayList<>();
        AgentScopeEventCollector collector = new AgentScopeEventCollector(
                logs::add
        );

        collector.handle(new TextBlockDeltaEvent(
                "r1",
                "b1",
                "I'll start by loading the audit skill."
        ).withSource("audit-supervisor-123_sql_injection"));
        collector.handle(new ToolCallStartEvent(
                "r1",
                "call-1",
                "load_skill_through_path"
        ).withSource("audit-supervisor-123_sql_injection"));
        collector.handle(new ToolResultEndEvent(
                "r1",
                "call-1",
                "load_skill_through_path",
                ToolResultState.SUCCESS
        ).withSource("audit-supervisor-123_sql_injection"));

        assertThat(logs).containsExactly(
                "[agentscope-audit-supervisor-123_sql_injection] "
                        + "I'll start by loading the audit skill.",
                "[agentscope-audit-supervisor-123_sql_injection] "
                        + "[tool-start] load_skill_through_path",
                "[agentscope-audit-supervisor-123_sql_injection] "
                        + "[tool-end] DONE load_skill_through_path"
        );
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
