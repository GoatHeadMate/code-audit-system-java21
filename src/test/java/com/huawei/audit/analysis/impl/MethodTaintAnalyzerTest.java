package com.huawei.audit.analysis.impl;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MethodTaintAnalyzerTest {

    @Test
    void detectsTaintFromParamThroughStringConcatToProcessBuilder() {
        MethodNode method = method(
                "Collector#buildCmd/1", "Collector", "buildCmd", 1,
                List.of(
                        callExpr("append", "cmd", "StringBuilder", 1,
                                "cmd.append(userInput)"),
                        callExpr("start", "ProcessBuilder", "ProcessBuilder", 0,
                                "new ProcessBuilder(\"/bin/bash\", \"-c\", cmd).start()")
                ),
                "String buildCmd(String userInput)"
        );
        Sink sink = new Sink(
                "s1", "COMMAND_EXECUTION", "ProcessBuilder.start()",
                "Collector#buildCmd/1", "Collector.java", 10,
                "new ProcessBuilder(\"/bin/bash\", \"-c\", userInput).start()"
        );

        var analyzer = new MethodTaintAnalyzer();
        var result = analyzer.findTaintSinks(List.of(method), List.of(sink));

        assertThat(result).singleElement().satisfies(s -> {
            assertThat(s.category()).isEqualTo("COMMAND_EXECUTION");
            assertThat(s.api()).contains("taint:");
            assertThat(s.methodId()).isEqualTo("Collector#buildCmd/1");
        });
    }

    @Test
    void detectsTaintFromParamThroughStringFormatToExec() {
        MethodNode method = method(
                "Strategy#collect/1", "Strategy", "collect", 1,
                List.of(
                        callExpr("format", "String", "String", 2,
                                "String.format(ZENITH_COMMAND, query)"),
                        callExpr("exec", "Runtime", "Runtime", 1,
                                "Runtime.getRuntime().exec(cmd)")
                ),
                "void collect(String query)"
        );
        Sink sink = new Sink(
                "s1", "COMMAND_EXECUTION", "Runtime.exec()",
                "Strategy#collect/1", "Strategy.java", 15,
                "Runtime.getRuntime().exec(query)"
        );

        var analyzer = new MethodTaintAnalyzer();
        var result = analyzer.findTaintSinks(List.of(method), List.of(sink));

        assertThat(result).singleElement().satisfies(s -> {
            assertThat(s.category()).isEqualTo("COMMAND_EXECUTION");
            assertThat(s.methodId()).isEqualTo("Strategy#collect/1");
        });
    }

    @Test
    void detectsTaintFromParamDirectlyInSinkExpression() {
        MethodNode method = method(
                "HeapBuilder#build/2", "HeapBuilder", "build", 2,
                List.of(
                        call("concat", "name", "String", 1),
                        call("start", "ProcessBuilder", "ProcessBuilder", 0)
                ),
                "void build(String name, String user)"
        );
        Sink sink = new Sink(
                "s1", "COMMAND_EXECUTION", "new ProcessBuilder",
                "HeapBuilder#build/2", "HeapBuilder.java", 20,
                "new ProcessBuilder(\"/bin/bash\", \"-c\", name).start()"
        );

        var analyzer = new MethodTaintAnalyzer();
        var result = analyzer.findTaintSinks(List.of(method), List.of(sink));

        assertThat(result).isNotEmpty();
    }

    @Test
    void skipsMethodsWithoutSinks() {
        MethodNode method = method(
                "Util#helper/1", "Util", "helper", 1,
                List.of(call("toString", "obj", "Object", 0)),
                "String helper(String input)"
        );

        var analyzer = new MethodTaintAnalyzer();
        var result = analyzer.findTaintSinks(List.of(method), List.of());

        assertThat(result).isEmpty();
    }

    @Test
    void skipsMethodsWithoutParameters() {
        MethodNode method = method(
                "Runner#run/0", "Runner", "run", 0,
                List.of(call("exec", "Runtime", "Runtime", 1)),
                "void run()"
        );
        Sink sink = new Sink(
                "s1", "COMMAND_EXECUTION", "Runtime.exec()",
                "Runner#run/0", "Runner.java", 5, "Runtime.exec()"
        );

        var analyzer = new MethodTaintAnalyzer();
        var result = analyzer.findTaintSinks(List.of(method), List.of(sink));

        assertThat(result).isEmpty();
    }

    private MethodNode method(
            String id, String className, String methodName,
            int parameterCount, List<CallSite> calls, String signature
    ) {
        return new MethodNode(
                id, className, methodName, parameterCount,
                List.of(),
                className + ".java", 1, 20, signature,
                calls, Map.of(), List.of(), List.of()
        );
    }

    private CallSite call(
            String methodName, String receiver,
            String receiverType, int argumentCount
    ) {
        return callExpr(methodName, receiver, receiverType, argumentCount,
                receiver + "." + methodName + "(arg)");
    }

    private CallSite callExpr(
            String methodName, String receiver,
            String receiverType, int argumentCount, String expression
    ) {
        return new CallSite(
                methodName, receiver, receiverType, argumentCount,
                List.of("String"), 1, expression
        );
    }
}
