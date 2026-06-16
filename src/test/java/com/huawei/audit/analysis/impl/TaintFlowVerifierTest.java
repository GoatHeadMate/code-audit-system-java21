package com.huawei.audit.analysis.impl;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallEdge;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.CandidatePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.EntryPoint;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodStep;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.TaintSummary;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class TaintFlowVerifierTest {
    private final TaintFlowVerifier verifier = new TaintFlowVerifier();

    @Test
    void doesNotInventParametersFromCommasInMethodBody() {
        CandidatePath candidate = candidate(
                "HTTP",
                "void run() { helper(first, second); }"
        );

        CandidatePath verified = verifier.verify(
                List.of(candidate),
                Map.of()
        ).getFirst();

        assertThat(verified.taintTrace().getFirst())
                .contains("no declared parameters")
                .doesNotContain("taint sources");
        assertThat(verified.sourceClassification()).isEqualTo("UNKNOWN");
    }

    @Test
    void treatsEventAndAsyncEntrypointsAsInternalTriggers() {
        for (String protocol : List.of("event", "async")) {
            CandidatePath verified = verifier.verify(
                    List.of(candidate(protocol, "void run(String value) {}")),
                    Map.of()
            ).getFirst();

            assertThat(verified.taintTrace().getFirst())
                    .contains("no external taint sources");
            assertThat(verified.sourceClassification())
                    .isEqualTo("INTERNAL_DERIVED");
        }
    }

    @Test
    void doesNotClassifyRequestDataAcrossAnUnconfirmedCallEdge() {
        CandidatePath base = candidate(
                "HTTP",
                "void run(String value) { service.execute(\"fixed\"); }"
        );
        MethodStep sinkStep = new MethodStep(
                "Service#execute/1",
                "Service",
                "execute",
                1,
                "Service.java",
                1,
                2,
                "void execute(String value)"
        );
        CandidatePath candidate = new CandidatePath(
                base.id(),
                base.entryPoint(),
                new Sink(
                        "sink-2",
                        "COMMAND_EXECUTION",
                        "new ProcessBuilder",
                        sinkStep.methodId(),
                        sinkStep.filePath(),
                        2,
                        "new ProcessBuilder(value)"
                ),
                List.of(base.methodPath().getFirst(), sinkStep),
                List.of(new CallEdge(
                        base.methodPath().getFirst().methodId(),
                        sinkStep.methodId(),
                        1,
                        "service.execute(\"fixed\")",
                        "receiver-type"
                )),
                "HIGH",
                1,
                "PENDING_CLAUDE_REVIEW",
                "PENDING",
                List.of(),
                "UNKNOWN"
        );
        TaintSummary entrySummary = new TaintSummary(
                base.methodPath().getFirst().methodId(),
                List.of(),
                Set.of(),
                false,
                false
        );

        CandidatePath verified = verifier.verify(
                List.of(candidate),
                Map.of(entrySummary.methodId(), entrySummary)
        ).getFirst();

        assertThat(verified.sourceClassification()).isEqualTo("UNKNOWN");
    }

    private CandidatePath candidate(String protocol, String signature) {
        EntryPoint entryPoint = new EntryPoint(
                "entry-1",
                protocol,
                List.of("POST"),
                "/run",
                "Controller",
                "run",
                "Controller.java",
                1,
                "spring",
                List.of(),
                "test",
                "HIGH",
                "Controller#run/0",
                "BOUND"
        );
        Sink sink = new Sink(
                "sink-1",
                "COMMAND_EXECUTION",
                "new ProcessBuilder",
                "Controller#run/0",
                "Controller.java",
                1,
                signature
        );
        MethodStep step = new MethodStep(
                "Controller#run/0",
                "Controller",
                "run",
                signature.contains("String value") ? 1 : 0,
                "Controller.java",
                1,
                1,
                signature
        );
        return new CandidatePath(
                "candidate-1",
                entryPoint,
                sink,
                List.of(step),
                List.of(),
                "HIGH",
                0,
                "PENDING_CLAUDE_REVIEW",
                "PENDING",
                List.of(),
                "UNKNOWN"
        );
    }
}
