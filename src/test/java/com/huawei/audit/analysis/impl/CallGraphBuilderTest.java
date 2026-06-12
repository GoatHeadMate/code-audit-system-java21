package com.huawei.audit.analysis.impl;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class CallGraphBuilderTest {
    @Test
    void resolvesOnlyImplementationMethodsWithMatchingArity() {
        MethodNode caller = method(
                "Caller#read/0",
                "Caller",
                "read",
                0,
                List.of(call("get", "values", "Map", 1))
        );
        MethodNode oneArgumentGet = method(
                "SimpleMap#get/1",
                "SimpleMap",
                "get",
                1,
                List.of()
        );
        MethodNode twoArgumentGet = method(
                "ExtendHashMap#get/2",
                "ExtendHashMap",
                "get",
                2,
                List.of()
        );
        SourceIndex index = SourceIndex.create(
                List.of(caller, oneArgumentGet, twoArgumentGet),
                List.of(),
                Map.of("Map", Set.of("SimpleMap", "ExtendHashMap")),
                List.of()
        );

        CallGraph graph = new CallGraphBuilder().build(index);

        assertThat(graph.outgoing().get(caller.id()))
                .extracting(edge -> edge.toMethodId())
                .containsExactly(oneArgumentGet.id());
    }

    @Test
    void doesNotUseUniqueMethodNameWhenArityDoesNotMatch() {
        MethodNode caller = method(
                "Caller#read/0",
                "Caller",
                "read",
                0,
                List.of(call("get", "unknown", "", 1))
        );
        MethodNode twoArgumentGet = method(
                "ExtendHashMap#get/2",
                "ExtendHashMap",
                "get",
                2,
                List.of()
        );
        SourceIndex index = SourceIndex.create(
                List.of(caller, twoArgumentGet),
                List.of(),
                Map.of(),
                List.of()
        );

        CallGraph graph = new CallGraphBuilder().build(index);

        assertThat(graph.outgoing().get(caller.id())).isEmpty();
        assertThat(graph.unresolvedCalls())
                .extracting(call -> call.expression())
                .containsExactly("unknown.get(arg)");
    }

    private MethodNode method(
            String id,
            String className,
            String methodName,
            int parameterCount,
            List<CallSite> calls
    ) {
        return new MethodNode(
                id,
                className,
                methodName,
                parameterCount,
                List.of(),
                className + ".java",
                1,
                1,
                methodName,
                calls,
                Map.of(),
                List.of(),
                List.of()
        );
    }

    private CallSite call(
            String methodName,
            String receiver,
            String receiverType,
            int argumentCount
    ) {
        return new CallSite(
                methodName,
                receiver,
                receiverType,
                argumentCount,
                List.of("Object"),
                1,
                receiver + "." + methodName + "(arg)"
        );
    }
}
