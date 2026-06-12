package com.huawei.audit.analysis.impl;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.TaintSummary;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MethodTaintSummarizerTest {

    private final MethodTaintSummarizer summarizer = new MethodTaintSummarizer();

    @Test
    void detectsDirectParameterFlowToCallArgument() {
        MethodNode method = new MethodNode(
                "Foo#bar/1@file:1:1",
                "Foo",
                "bar",
                1,
                List.of("input"),
                "file.java",
                1, 10,
                "void bar(String input) { exec(input); }",
                List.of(new CallSite(
                        "exec", "", "", 1,
                        List.of("String"),
                        5,
                        "exec(input)"
                )),
                Map.of("input", "String"),
                List.of(),
                List.of()
        );

        TaintSummary summary = summarizer.summarize(method);
        assertThat(summary.parameterFlows())
                .anyMatch(flow ->
                        flow.sourceParamIndex() == 0
                                && flow.targetCallMethodName().equals("exec")
                                && flow.propagationType().equals("direct")
                );
    }

    @Test
    void detectsReplaceAsTaintPropagator() {
        MethodNode method = new MethodNode(
                "Util#gen/2@file:1:1",
                "Util",
                "gen",
                2,
                List.of("template", "value"),
                "file.java",
                1, 10,
                "String gen(String template, String value) { return template.replace(key, value); }",
                List.of(new CallSite(
                        "replace", "template", "String", 2,
                        List.of("String", "String"),
                        5,
                        "template.replace(\"${key}\", value)"
                )),
                Map.of("template", "String", "value", "String"),
                List.of(),
                List.of()
        );

        TaintSummary summary = summarizer.summarize(method);
        assertThat(summary.hasTaintPropagation()).isTrue();
        assertThat(summary.hasStringManipulation()).isTrue();
        assertThat(summary.parameterFlows())
                .anyMatch(flow ->
                        flow.sourceParamIndex() == 1
                                && flow.propagationType().equals("replace")
                );
    }

    @Test
    void emptyMethodHasNoTaint() {
        MethodNode method = new MethodNode(
                "Empty#noop/0@file:1:1",
                "Empty",
                "noop",
                0,
                List.of(),
                "file.java",
                1, 5,
                "void noop() {}",
                List.of(),
                Map.of(),
                List.of(),
                List.of()
        );

        TaintSummary summary = summarizer.summarize(method);
        assertThat(summary.parameterFlows()).isEmpty();
        assertThat(summary.hasTaintPropagation()).isFalse();
    }
}
