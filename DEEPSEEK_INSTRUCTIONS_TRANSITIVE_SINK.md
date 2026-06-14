# DeepSeek 指令：传递性 Sink 发现 + split 污点传播

## 背景

当前审计系统无法发现 Chain G 漏洞：
```
checkName 用户输入 → 字符串拼接 → .split(" ") → RuntimeExec.executeAndGetReturnMsg() → Runtime.exec()
```

两个根本原因：
1. `RuntimeExec.exec()` 是 `Runtime.exec()` 的包装器，但不在静态 sink 列表中，调用图到它就断了
2. `.split()` 不被视为污点传播器，污点在 split 处丢失

## 变更概述

| # | 类型 | 文件 | 说明 |
|---|------|------|------|
| 1 | 修改 | `MethodTaintSummarizer.java` | `split` 加入两个传播器集合 + `inferPropagationType` 增加 split 分支 |
| 2 | 新建 | `TransitiveSinkResolver.java` | 遍历调用图，标记一跳即达已知 sink 且传递参数的方法为派生 sink |
| 3 | 修改 | `WhiteBoxAnalysisServiceImpl.java` | 在调用图构建后、路径查找前插入传递性 sink 解析 |
| 4 | 修改 | `TaintFlowVerifier.java` | propagationType switch 增加 `"split"` 分支 |
| 5 | 修改 | `WhiteBoxAnalysisServiceTest.java` | 新增测试用例：验证 concat+split+wrapper exec 模式可被检测 |

---

## 变更 1：MethodTaintSummarizer.java

文件路径：`src/main/java/com/huawei/audit/analysis/impl/MethodTaintSummarizer.java`

### 1a. `STRING_PROPAGATORS` 集合加入 `"split"`

当前代码（第 16-22 行）：
```java
private static final Set<String> STRING_PROPAGATORS = Set.of(
        "replace", "replaceAll", "replaceFirst",
        "format", "formatted",
        "concat", "substring", "trim", "strip",
        "toLowerCase", "toUpperCase",
        "append", "insert", "toString"
);
```

改为：
```java
private static final Set<String> STRING_PROPAGATORS = Set.of(
        "replace", "replaceAll", "replaceFirst",
        "format", "formatted",
        "concat", "substring", "trim", "strip",
        "toLowerCase", "toUpperCase",
        "append", "insert", "toString",
        "split"
);
```

### 1b. `TAINT_PROPAGATOR_METHODS` 集合加入 `"split"`

当前代码（第 23-27 行）：
```java
private static final Set<String> TAINT_PROPAGATOR_METHODS = Set.of(
        "replace", "replaceAll", "replaceFirst",
        "format", "formatted",
        "append"
);
```

改为：
```java
private static final Set<String> TAINT_PROPAGATOR_METHODS = Set.of(
        "replace", "replaceAll", "replaceFirst",
        "format", "formatted",
        "append",
        "split"
);
```

### 1c. `inferPropagationType` 方法增加 split 分支

当前代码（第 129-143 行）：
```java
private String inferPropagationType(String methodName) {
    if (Set.of("replace", "replaceAll", "replaceFirst").contains(methodName)) {
        return "replace";
    }
    if (Set.of("format", "formatted").contains(methodName)) {
        return "format";
    }
    if ("append".equals(methodName)) {
        return "concatenation";
    }
    if ("<init>".equals(methodName)) {
        return "constructor-arg";
    }
    return "direct";
}
```

改为：
```java
private String inferPropagationType(String methodName) {
    if (Set.of("replace", "replaceAll", "replaceFirst").contains(methodName)) {
        return "replace";
    }
    if (Set.of("format", "formatted").contains(methodName)) {
        return "format";
    }
    if ("append".equals(methodName)) {
        return "concatenation";
    }
    if ("split".equals(methodName)) {
        return "split";
    }
    if ("<init>".equals(methodName)) {
        return "constructor-arg";
    }
    return "direct";
}
```

---

## 变更 2：新建 TransitiveSinkResolver.java

文件路径：`src/main/java/com/huawei/audit/analysis/impl/TransitiveSinkResolver.java`

完整内容：

```java
package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallEdge;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 查找"传递性 sink"：自身不在静态 sink 列表中，但一跳内调用了已知 sink 并传递参数的方法。
 * 典型场景：RuntimeExec.exec(cmd) 内部调用 Runtime.getRuntime().exec(cmd)。
 */
final class TransitiveSinkResolver {

    List<Sink> resolve(SourceIndex index, CallGraph callGraph) {
        Set<String> existingSinkMethodIds = new LinkedHashSet<>();
        Map<String, String> sinkCategoryByMethodId = new LinkedHashMap<>();
        for (Sink sink : index.sinks()) {
            existingSinkMethodIds.add(sink.methodId());
            sinkCategoryByMethodId.put(sink.methodId(), sink.category());
        }

        List<Sink> derivedSinks = new ArrayList<>();
        int sequence = index.sinks().size();

        for (MethodNode method : index.methods()) {
            if (existingSinkMethodIds.contains(method.id())) {
                continue;
            }

            List<CallEdge> edges = callGraph.outgoing()
                    .getOrDefault(method.id(), List.of());

            for (CallEdge edge : edges) {
                String targetId = edge.toMethodId();
                String category = sinkCategoryByMethodId.get(targetId);
                if (category == null) {
                    continue;
                }

                if (!forwardsParameter(method, edge)) {
                    continue;
                }

                sequence++;
                derivedSinks.add(new Sink(
                        "sink-derived-" + sequence,
                        category,
                        "transitive:" + abbreviate(targetId),
                        method.id(),
                        method.filePath(),
                        edge.line(),
                        edge.expression()
                ));
                existingSinkMethodIds.add(method.id());
                sinkCategoryByMethodId.put(method.id(), category);
                break;
            }
        }

        return List.copyOf(derivedSinks);
    }

    private boolean forwardsParameter(MethodNode method, CallEdge edge) {
        if (method.parameterCount() == 0) {
            return false;
        }
        for (CallSite call : method.calls()) {
            if (call.line() == edge.line() && call.argumentCount() > 0) {
                String expression = call.expression() != null ? call.expression() : "";
                for (String paramName : method.parameterNames()) {
                    if (expression.contains(paramName)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private String abbreviate(String methodId) {
        int atIdx = methodId.indexOf('@');
        return atIdx > 0 ? methodId.substring(0, atIdx) : methodId;
    }
}
```

**设计说明：**
- 遍历所有方法，跳过已是 sink 的方法
- 对每个方法查看其调用图出边，如果目标方法是已知 sink，且当前方法的参数出现在该调用表达式中（`forwardsParameter`），则当前方法也被标记为同类别的 "派生 sink"
- 只做一跳（直接调用已知 sink），不做多跳传递（避免过度扩展）
- 派生 sink 的 id 前缀为 `sink-derived-`，api 前缀为 `transitive:`，便于区分

---

## 变更 3：WhiteBoxAnalysisServiceImpl.java

文件路径：`src/main/java/com/huawei/audit/analysis/impl/WhiteBoxAnalysisServiceImpl.java`

### 3a. 新增字段

在现有字段声明区（第 33-34 行 `taintSummarizer` 和 `taintFlowVerifier` 之后）添加：

```java
private final TransitiveSinkResolver transitiveSinkResolver;
```

### 3b. 构造函数中初始化

在构造函数中（第 49-50 行 `taintSummarizer` 和 `taintFlowVerifier` 初始化之后）添加：

```java
this.transitiveSinkResolver = new TransitiveSinkResolver();
```

### 3c. analyze 方法中插入传递性 sink 解析

当前代码（第 82-91 行）：
```java
        CallGraph callGraph = callGraphBuilder.build(finalIndex);
        List<EntryPoint> entryPoints = entryPointBinder.bind(
                discovered,
                finalIndex
        );
        List<CandidatePath> candidates = candidatePathFinder.find(
                entryPoints,
                finalIndex,
                callGraph
        );
```

改为：
```java
        CallGraph callGraph = callGraphBuilder.build(finalIndex);

        List<Sink> transitiveSinks = transitiveSinkResolver.resolve(
                finalIndex, callGraph);
        SourceIndex enrichedIndex = finalIndex.withAdditionalSinks(transitiveSinks);

        List<EntryPoint> entryPoints = entryPointBinder.bind(
                discovered,
                enrichedIndex
        );
        List<CandidatePath> candidates = candidatePathFinder.find(
                entryPoints,
                enrichedIndex,
                callGraph
        );
```

### 3d. 后续所有 `finalIndex` 引用改为 `enrichedIndex`

在改动之后的代码中，将所有剩余的 `finalIndex` 替换为 `enrichedIndex`。具体涉及：

第 93-94 行（taintSummarizer 调用）：
```java
        Map<String, TaintSummary> taintSummaries =
                taintSummarizer.summarizeAll(enrichedIndex.methods());
```

第 98-100 行（storageWritePathFinder 调用）：
```java
        List<StorageWritePath> writePaths = storageWritePathFinder.find(
                entryPoints,
                enrichedIndex,
                callGraph
        );
```

第 103-108 行（storedCandidateCorrelator 调用）：
```java
        List<StoredCandidate> storedCandidates =
                storedCandidateCorrelator.correlate(
                        writePaths,
                        taintVerifiedCandidates,
                        enrichedIndex
                );
```

第 109-128 行（return AnalysisResult）：
```java
        return new AnalysisResult(
                entryPoints,
                enrichedIndex.sinks(),
                taintVerifiedCandidates,
                enrichedIndex.storageAccesses(),
                storedCandidates,
                callGraph.unresolvedCalls(),
                enrichedIndex.parseErrors(),
                coverageCalculator.calculate(
                        sourceRoot,
                        enrichedIndex,
                        callGraph,
                        entryPoints,
                        taintVerifiedCandidates,
                        storedCandidates,
                        extraRules.size(),
                        llmReviewedSinks.size()
                ),
                Map.copyOf(taintSummaries)
        );
```

---

## 变更 4：TaintFlowVerifier.java

文件路径：`src/main/java/com/huawei/audit/analysis/impl/TaintFlowVerifier.java`

在第 93-98 行 `propagationType` 的 switch 表达式中增加 `"split"` 分支：

当前代码：
```java
                    String propDesc = switch (flow.propagationType()) {
                        case "replace" -> "via String.replace() template substitution";
                        case "format" -> "via String.format()";
                        case "concatenation" -> "via string concatenation";
                        case "constructor-arg" -> "via constructor parameter";
                        default -> "via direct argument passing";
                    };
```

改为：
```java
                    String propDesc = switch (flow.propagationType()) {
                        case "replace" -> "via String.replace() template substitution";
                        case "format" -> "via String.format()";
                        case "concatenation" -> "via string concatenation";
                        case "split" -> "via String.split() preserving taint in array elements";
                        case "constructor-arg" -> "via constructor parameter";
                        default -> "via direct argument passing";
                    };
```

同时，在第 101-103 行增加 `split` 也触发 `hasStringPropagation`：

当前代码：
```java
                    if ("replace".equals(flow.propagationType())
                            || "format".equals(flow.propagationType())) {
                        hasStringPropagation = true;
                    }
```

改为：
```java
                    if ("replace".equals(flow.propagationType())
                            || "format".equals(flow.propagationType())
                            || "split".equals(flow.propagationType())) {
                        hasStringPropagation = true;
                    }
```

---

## 变更 5：WhiteBoxAnalysisServiceTest.java

文件路径：`src/test/java/com/huawei/audit/analysis/WhiteBoxAnalysisServiceTest.java`

在现有测试类中新增一个测试方法（追加在最后一个测试方法之后、类的闭合大括号之前）：

```java
@Test
void detectsArgumentInjectionThroughSplitAndWrapperExec() throws Exception {
    String source = """
            package com.example;
            import javax.ws.rs.*;
            @Path("/dpfault/task/v1")
            public class TaskCheckService {
                @GET @Path("/check/{type}")
                public String check(@QueryParam("checkName") String checkName) {
                    String ip = "10.0.0.1";
                    getOpenGeminiTag(ip, checkName);
                    return "ok";
                }
                private String getOpenGeminiTag(String ip, String checkName) {
                    String cmd = "/bin/bash /opt/script.sh " + ip + " " + checkName;
                    return RuntimeExec.executeAndGetReturnMsg(cmd.split(" "));
                }
            }
            """;
    String wrapperSource = """
            package com.example;
            public class RuntimeExec {
                public static String executeAndGetReturnMsg(String[] commands) {
                    try {
                        Process p = Runtime.getRuntime().exec(commands);
                        return new String(p.getInputStream().readAllBytes());
                    } catch (Exception e) { return ""; }
                }
            }
            """;
    Path root = writeSource(source, "com/example/TaskCheckService.java");
    writeSourceAt(root, wrapperSource, "com/example/RuntimeExec.java");
    AnalysisResult result = service.analyze(root, List.of(), null, null);

    assertThat(result.candidatePaths())
            .as("should find path through split() + wrapper exec to Runtime.exec sink")
            .isNotEmpty();
    assertThat(result.candidatePaths())
            .anyMatch(path ->
                    path.sink().category().equals("COMMAND_EXECUTION")
                            && path.entryPoint().path().contains("/check"));
}
```

**关于辅助方法 `writeSourceAt`**：如果测试类中现有的 `writeSource` 方法只接受源码和相对路径、返回 root 目录，那么新增一个重载方法，接受已有 root 目录、源码和相对路径：

```java
private void writeSourceAt(Path root, String source, String relativePath) throws Exception {
    Path file = root.resolve(relativePath);
    Files.createDirectories(file.getParent());
    Files.writeString(file, source);
}
```

如果 `writeSource` 方法的实际签名不同，请根据现有实现调整。关键是确保两个 Java 文件写入同一个 source root 目录下。

---

## 验证

完成以上 5 项变更后，运行：
```
mvn compile test
```

预期：
- 所有既有测试通过
- 新测试 `detectsArgumentInjectionThroughSplitAndWrapperExec` 通过
- `TransitiveSinkResolver` 能从 `RuntimeExec.executeAndGetReturnMsg` → `Runtime.exec()` 推导出 `RuntimeExec.executeAndGetReturnMsg` 是 COMMAND_EXECUTION 派生 sink
- `MethodTaintSummarizer` 能追踪通过 `.split()` 的污点传播

## 不需要修改的文件

- `DangerousSinkClassifier.java` — `Runtime.exec()` 已经在静态规则中（第 26 行），不需要改
- `CallGraphBuilder.java` — 调用图构建逻辑不需要改
- `SourceIndex.java` — `withAdditionalSinks()` 方法已存在，不需要改
- `WhiteBoxAnalysisService.java`（接口） — 无新 record 需要添加
