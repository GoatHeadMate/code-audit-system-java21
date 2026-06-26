package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class AgentScopeTextBufferTest {

    @Test
    void combinesTokenDeltasBeforePublishingSupervisorLog() {
        AgentScopeTextBuffer buffer = new AgentScopeTextBuffer(
                "[agentscope-supervisor]"
        );
        List<String> logs = new ArrayList<>();

        buffer.append("I", logs::add);
        buffer.append("'ll", logs::add);
        buffer.append(" start", logs::add);
        buffer.append(" by reading results.", logs::add);

        assertThat(logs).containsExactly(
                "[agentscope-supervisor] I'll start by reading results."
        );
        assertThat(buffer.transcript())
                .isEqualTo("I'll start by reading results.");
    }

    @Test
    void flushesPartialTextAtToolBoundaries() {
        AgentScopeTextBuffer buffer = new AgentScopeTextBuffer(
                "[agentscope-supervisor]"
        );
        List<String> logs = new ArrayList<>();

        buffer.append("Starting hunter", logs::add);
        buffer.flush(logs::add);

        assertThat(logs).containsExactly(
                "[agentscope-supervisor] Starting hunter"
        );
    }

    @Test
    void doesNotSplitOnJsonFieldPunctuation() {
        AgentScopeTextBuffer buffer = new AgentScopeTextBuffer(
                "[agentscope-supervisor]"
        );
        List<String> logs = new ArrayList<>();

        buffer.append("\"candidate_count\":", logs::add);
        buffer.append("0}", logs::add);

        assertThat(logs).containsExactly(
                "[agentscope-supervisor] \"candidate_count\":0}"
        );
    }
}
