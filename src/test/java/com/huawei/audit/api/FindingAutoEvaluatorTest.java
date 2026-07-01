package com.huawei.audit.api;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class FindingAutoEvaluatorTest {
    private final FindingAutoEvaluator evaluator = new FindingAutoEvaluator();

    @Test
    void confirmsHighConfidenceFindingWithEvidence() {
        var evaluations = evaluator.evaluate(List.of(Map.of(
                "verdict", "CONFIRM",
                "severity", "HIGH",
                "confidence", "HIGH",
                "message", "request parameter reaches Runtime.exec"
        )));

        assertThat(evaluations).singleElement().satisfies(evaluation -> {
            assertThat(evaluation.findingIndex()).isZero();
            assertThat(evaluation.verdict()).isEqualTo("CONFIRM");
            assertThat(evaluation.recorded()).isTrue();
        });
    }

    @Test
    void keepsLowConfidenceFindingForReview() {
        var evaluations = evaluator.evaluate(List.of(Map.of(
                "severity", "HIGH",
                "confidence", "LOW",
                "message", "weak evidence"
        )));

        assertThat(evaluations).singleElement().satisfies(evaluation -> {
            assertThat(evaluation.verdict()).isEqualTo("NEEDS_REVIEW");
            assertThat(evaluation.learningNote()).contains("先验");
        });
    }

    @Test
    void pocSuccessOverridesOtherSignals() {
        var evaluations = evaluator.evaluate(List.of(Map.of(
                "severity", "LOW",
                "confidence", "LOW",
                "poc_status", "success"
        )));

        assertThat(evaluations).singleElement().satisfies(evaluation -> {
            assertThat(evaluation.verdict()).isEqualTo("POC_SUCCESS");
            assertThat(evaluation.pocStatus()).isEqualTo("SUCCESS");
        });
    }
}
