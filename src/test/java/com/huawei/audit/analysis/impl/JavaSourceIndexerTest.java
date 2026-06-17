package com.huawei.audit.analysis.impl;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JavaSourceIndexerTest {

    @TempDir
    Path tempDir;

    @AfterEach
    void clearSymbolSolverFlag() {
        System.clearProperty("audit.symbol-solver");
    }

    @Test
    void indexesSourcesAcrossParserBatches() throws Exception {
        for (int index = 0; index < 140; index++) {
            Files.writeString(
                    tempDir.resolve("Service" + index + ".java"),
                    "class Service" + index
                            + " { void execute() { helper(); }"
                            + " void helper() { } }"
            );
        }

        SourceIndex result = new JavaSourceIndexer().build(tempDir, List.of());

        assertThat(result.methods()).hasSize(280);
        assertThat(result.parseErrors()).isEmpty();
    }

    @Test
    void symbolSolverResolvesChainedReceiverTypeWhenEnabled() throws Exception {
        Files.writeString(
                tempDir.resolve("Helper.java"),
                "class Helper { void doWork() {} }"
        );
        Files.writeString(
                tempDir.resolve("Demo.java"),
                "class Demo {"
                        + " Helper getHelper() { return new Helper(); }"
                        + " void run() { getHelper().doWork(); } }"
        );

        // Disabled (default): the lexical heuristic cannot type a chained call.
        String heuristic = receiverTypeOfDoWork(
                new JavaSourceIndexer().build(tempDir, List.of())
        );
        assertThat(heuristic).isEmpty();

        // Enabled: the symbol solver resolves getHelper() -> Helper.
        System.setProperty("audit.symbol-solver", "true");
        String resolved = receiverTypeOfDoWork(
                new JavaSourceIndexer().build(tempDir, List.of())
        );
        assertThat(resolved).isEqualTo("Helper");
    }

    private static String receiverTypeOfDoWork(SourceIndex index) {
        return index.methods().stream()
                .filter(method -> method.methodName().equals("run"))
                .map(MethodNode::calls)
                .flatMap(List::stream)
                .filter(call -> call.methodName().equals("doWork"))
                .map(CallSite::receiverType)
                .findFirst()
                .orElseThrow();
    }
}
