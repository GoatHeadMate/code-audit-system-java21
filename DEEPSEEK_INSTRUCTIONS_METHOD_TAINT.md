# 方法级污点追踪增强 — DeepSeek 修改指令

## 问题背景

当前系统在审计 DPFaultHorizonService 时，成功发现了 heap/cmd/log/trace 四个端点的直接命令注入（参数直接拼接到 `bash -c`），但**遗漏了最关键的漏洞**：

**`createCollectionTask` → `extensionParams` → `TaskUtil.generateQuery()` → `String.replace("${key}", userInput)` → 双引号 shell 命令 → `ProcessBuilder("/bin/bash", "-c", cmd)` → RCE**

这条链是整个服务中攻击面最广的 RCE 漏洞（影响所有配置了 `extensionParams` 占位符的采集场景），但系统未能发现。

### 遗漏的根因分析

经过逐文件分析，确定了三个根因：

**根因 1：构造函数调用未被追踪为调用边**
`MethodBodyIndexer.visitNewClass()` 只检查特定类型（ProcessBuilder、XMLDecoder 等）并添加 sink，但**不记录 CallSite**。这意味着 `new CollectionTaskExecutor(taskId, scenarios, ...)` 这样的构造函数调用不会产生调用图边，数据无法通过构造函数参数传递被追踪。

**根因 2：最大路径深度不足**
`CandidatePathFinder.MAX_PATH_DEPTH = 12`，而 createCollectionTask 的完整调用链深度约 13-15 步：
```
createCollectionTask → CreateCollectionTask.createMainTask → 
  CollectionTaskManager.registerTask → pool.submit → 
  CollectionTaskExecutor.run → executeTask → executeScenariosCollection →
  executeSingleCollector → strategy.collect → generateQuery → 
  TaskUtil.generateQuery → (replace) → executeCommand → ProcessBuilder.start
```

**根因 3：缺少方法级污点追踪**
系统找到结构性路径（入口→sink），但不验证用户可控数据是否实际流经该路径。这导致：
- 候选路径缺乏数据流证据，hunter 子代理无法判断 `extensionParams` 是否真的流到了 `ProcessBuilder`
- 模板替换模式 `String.replace("${key}", userInput)` 的污点传播未被识别

---

## 修改架构总览

需要修改/新增以下文件（全部在 `src/main/java/com/huawei/audit/analysis/` 下）：

| 文件 | 动作 | 说明 |
|------|------|------|
| `WhiteBoxAnalysisService.java` | 修改 | MethodNode 增加 `parameterNames`；CandidatePath 增加 `taintConfidence` + `taintTrace`；新增 `TaintSummary`、`TaintFlow` record |
| `impl/MethodBodyIndexer.java` | 修改 | `visitNewClass` 增加构造函数 CallSite 记录 |
| `impl/CompilationUnitIndexer.java` | 修改 | 收集参数名列表传给 MethodNode |
| `impl/CandidatePathFinder.java` | 修改 | MAX_PATH_DEPTH 从 12 改为 20 |
| `impl/MethodTaintSummarizer.java` | **新增** | 基于 MethodNode 数据计算每个方法的污点摘要 |
| `impl/TaintFlowVerifier.java` | **新增** | 沿候选路径验证污点是否从入口流到 sink |
| `impl/WhiteBoxAnalysisServiceImpl.java` | 修改 | 集成污点摘要计算和污点验证 |
| `impl/CoverageCalculator.java` | 修改 | Coverage 统计增加污点相关指标 |

测试文件：
| 文件 | 动作 |
|------|------|
| `test/.../WhiteBoxAnalysisServiceTest.java` | 修改：增加模板替换命令注入测试用例 |
| `test/.../impl/MethodTaintSummarizerTest.java` | **新增** |
| `test/.../impl/TaintFlowVerifierTest.java` | **新增** |
| 其余已有测试 | 修改：适配 MethodNode 新字段和 CandidatePath 新字段 |

---

## 修改 1：WhiteBoxAnalysisService.java 接口增强

**文件**：`src/main/java/com/huawei/audit/analysis/WhiteBoxAnalysisService.java`

### 1.1 MethodNode 增加 parameterNames

将 MethodNode record 从：
```java
record MethodNode(
        String id,
        String className,
        String methodName,
        int parameterCount,
        String filePath,
        int startLine,
        int endLine,
        String signature,
        List<CallSite> calls,
        Map<String, String> variableTypes,
        List<String> methodReferences,
        List<StorageAccess> storageAccesses
) { }
```

改为：
```java
record MethodNode(
        String id,
        String className,
        String methodName,
        int parameterCount,
        List<String> parameterNames,    // ← 新增
        String filePath,
        int startLine,
        int endLine,
        String signature,
        List<CallSite> calls,
        Map<String, String> variableTypes,
        List<String> methodReferences,
        List<StorageAccess> storageAccesses
) { }
```

### 1.2 CandidatePath 增加污点信息

将 CandidatePath record 从：
```java
record CandidatePath(
        String id,
        EntryPoint entryPoint,
        Sink sink,
        List<MethodStep> methodPath,
        List<CallEdge> callEdges,
        String staticConfidence,
        int callDepth,
        String reviewStatus
) { }
```

改为：
```java
record CandidatePath(
        String id,
        EntryPoint entryPoint,
        Sink sink,
        List<MethodStep> methodPath,
        List<CallEdge> callEdges,
        String staticConfidence,
        int callDepth,
        String reviewStatus,
        String taintConfidence,     // ← 新增："CONFIRMED", "LIKELY", "STRUCTURAL", "NONE"
        List<String> taintTrace     // ← 新增：每步污点传播的文字描述
) { }
```

### 1.3 新增 TaintSummary 和 TaintFlow record

在 WhiteBoxAnalysisService 接口中添加：

```java
record TaintFlow(
        int sourceParamIndex,
        String targetCallMethodName,
        String targetCallReceiver,
        int targetArgIndex,
        String propagationType      // "direct", "concatenation", "replace", "format", "constructor-arg"
) { }

record TaintSummary(
        String methodId,
        List<TaintFlow> parameterFlows,     // 参数 → 调用参数的流
        Set<Integer> paramsThatReachReturn,  // 哪些参数流向了 return 值
        boolean hasStringManipulation,       // 是否包含 replace/format 等字符串操作
        boolean hasTaintPropagation          // 是否有污点传播（replace/format 结果被使用）
) { }
```

### 1.4 AnalysisResult 增加污点摘要

将 AnalysisResult 从：
```java
record AnalysisResult(
        List<EntryPoint> entryPoints,
        List<Sink> sinks,
        List<CandidatePath> candidatePaths,
        List<StorageAccess> storageAccesses,
        List<StoredCandidate> storedCandidates,
        List<UnresolvedCall> unresolvedCalls,
        List<String> parserDiagnostics,
        Coverage coverage
) { }
```

改为：
```java
record AnalysisResult(
        List<EntryPoint> entryPoints,
        List<Sink> sinks,
        List<CandidatePath> candidatePaths,
        List<StorageAccess> storageAccesses,
        List<StoredCandidate> storedCandidates,
        List<UnresolvedCall> unresolvedCalls,
        List<String> parserDiagnostics,
        Coverage coverage,
        Map<String, TaintSummary> taintSummaries   // ← 新增：methodId → TaintSummary
) { }
```

---

## 修改 2：MethodBodyIndexer — 构造函数调用追踪

**文件**：`src/main/java/com/huawei/audit/analysis/impl/MethodBodyIndexer.java`

### 2.1 在 visitNewClass 中记录构造函数 CallSite

当前的 `visitNewClass` 只对特定类型（ProcessBuilder 等）添加 sink。修改为：在现有 sink 检查之后，对**所有** `new X(args)` 调用记录一个 CallSite，使调用图可以跟踪构造函数参数。

将当前代码：
```java
@Override
public Void visitNewClass(NewClassTree tree, Void unused) {
    String type = AnalysisTextUtils.simpleName(tree.getIdentifier().toString());
    if ("ProcessBuilder".equals(type)) {
        addSink("COMMAND_EXECUTION", "new ProcessBuilder", tree);
    } else if ("XMLDecoder".equals(type)) {
        addSink("NATIVE_DESERIALIZATION", "new XMLDecoder", tree);
    } else if ("URLClassLoader".equals(type)) {
        addSink("DYNAMIC_LOADING", "new URLClassLoader", tree);
    } else if ("RedirectView".equals(type)) {
        addSink("HTTP_REDIRECT", "new RedirectView", tree);
    } else if (Set.of(
            "FileOutputStream",
            "FileWriter",
            "RandomAccessFile"
    ).contains(type)) {
        addSink("FILE_WRITE", "new " + type, tree);
    }
    return super.visitNewClass(tree, unused);
}
```

改为：
```java
@Override
public Void visitNewClass(NewClassTree tree, Void unused) {
    String type = AnalysisTextUtils.simpleName(tree.getIdentifier().toString());
    if ("ProcessBuilder".equals(type)) {
        addSink("COMMAND_EXECUTION", "new ProcessBuilder", tree);
    } else if ("XMLDecoder".equals(type)) {
        addSink("NATIVE_DESERIALIZATION", "new XMLDecoder", tree);
    } else if ("URLClassLoader".equals(type)) {
        addSink("DYNAMIC_LOADING", "new URLClassLoader", tree);
    } else if ("RedirectView".equals(type)) {
        addSink("HTTP_REDIRECT", "new RedirectView", tree);
    } else if (Set.of(
            "FileOutputStream",
            "FileWriter",
            "RandomAccessFile"
    ).contains(type)) {
        addSink("FILE_WRITE", "new " + type, tree);
    }

    // 为所有构造函数调用记录 CallSite，使调用图可以跟踪数据流
    if (tree.getArguments() != null && !tree.getArguments().isEmpty()) {
        calls.add(new CallSite(
                "<init>",
                "",
                type,
                tree.getArguments().size(),
                tree.getArguments().stream()
                        .map(this::expressionType)
                        .toList(),
                source.line(tree, true),
                source.sourceText(tree, 500)
        ));
    }
    return super.visitNewClass(tree, unused);
}
```

**关键点**：
- methodName 使用 `"<init>"`，与 Java 编译器 AST 中构造函数的名称一致
- receiver 为空字符串（构造函数没有 receiver）
- receiverType 为类名（如 `"CollectionTaskExecutor"`）
- 只对有参数的构造函数记录（无参构造函数不传递数据，没有追踪价值）

### 2.2 CallGraphBuilder 已能解析 `<init>` 调用

`CallGraphBuilder.addClassTargets` 使用 `className + "#" + call.methodName()` 作为 key 查找目标方法。由于 `CompilationUnitIndexer.visitMethod` 中构造函数的 `tree.getName().toString()` 返回 `"<init>"`，构造函数已被索引为 `ClassName#<init>/N@file:line:seq`。因此 `addClassTargets` 会查找 `ClassName#<init>` 并匹配到构造函数方法节点。

**不需要修改 CallGraphBuilder**。

---

## 修改 3：CompilationUnitIndexer — 收集参数名

**文件**：`src/main/java/com/huawei/audit/analysis/impl/CompilationUnitIndexer.java`

在 `visitMethod` 中，在现有参数类型收集之后，额外收集参数名列表：

找到以下代码段（约第 114-122 行）：
```java
Map<String, String> variableTypes = new LinkedHashMap<>(
        owner.fieldTypes()
);
for (VariableTree parameter : tree.getParameters()) {
    variableTypes.put(
            parameter.getName().toString(),
            AnalysisTextUtils.simpleName(parameter.getType().toString())
    );
}
```

在其后追加：
```java
List<String> parameterNames = tree.getParameters().stream()
        .map(parameter -> parameter.getName().toString())
        .toList();
```

然后修改 MethodNode 构造，在 `parameterCount` 后加入 `parameterNames`：

将：
```java
methods.add(new MethodNode(
        methodId,
        owner.className(),
        methodName,
        tree.getParameters().size(),
        filePath,
        // ... 其余字段
));
```

改为：
```java
methods.add(new MethodNode(
        methodId,
        owner.className(),
        methodName,
        tree.getParameters().size(),
        List.copyOf(parameterNames),   // ← 新增
        filePath,
        // ... 其余字段不变
));
```

---

## 修改 4：CandidatePathFinder — 增加最大深度

**文件**：`src/main/java/com/huawei/audit/analysis/impl/CandidatePathFinder.java`

将：
```java
private static final int MAX_PATH_DEPTH = 12;
```

改为：
```java
private static final int MAX_PATH_DEPTH = 20;
```

同时在 `ReverseReachability.distances` 的调用处确保使用相同的新深度值（第 37 行已引用 `MAX_PATH_DEPTH`，无需额外修改）。

### 4.1 修改 CandidatePath 构建以包含污点字段

在 `find()` 方法中构建 CandidatePath 的地方（约第 65 行），初始时将 taintConfidence 设为 `"PENDING"` 并将 taintTrace 设为空列表：

将：
```java
candidates.add(new CandidatePath(
        "candidate-" + sequence++,
        entryPoint,
        sink,
        toSteps(state.methodPath(), index),
        state.edges(),
        confidence(state.edges()),
        state.edges().size(),
        "PENDING_CLAUDE_REVIEW"
));
```

改为：
```java
candidates.add(new CandidatePath(
        "candidate-" + sequence++,
        entryPoint,
        sink,
        toSteps(state.methodPath(), index),
        state.edges(),
        confidence(state.edges()),
        state.edges().size(),
        "PENDING_CLAUDE_REVIEW",
        "PENDING",          // taintConfidence — 稍后由 TaintFlowVerifier 填充
        List.of()           // taintTrace — 稍后由 TaintFlowVerifier 填充
));
```

---

## 修改 5：新增 MethodTaintSummarizer

**新文件**：`src/main/java/com/huawei/audit/analysis/impl/MethodTaintSummarizer.java`

此类对每个 MethodNode 执行轻量级方法内污点分析，计算 TaintSummary。

### 核心算法

对每个方法：
1. 初始化污点集合：每个参数名 → 对应的参数索引
2. 遍历方法的 `variableTypes` 和 `calls`：
   - 对每个调用站点，检查其参数是否引用了被污染的变量
   - 对字符串操作（replace、replaceAll、format、append、concat），标记返回值/接收者继承污点
   - 对赋值操作（通过变量类型推断），传播污点
3. 检查方法签名/代码中是否有 return 语句引用了被污染的变量

```java
package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.TaintFlow;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.TaintSummary;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class MethodTaintSummarizer {
    private static final Set<String> STRING_PROPAGATORS = Set.of(
            "replace", "replaceAll", "replaceFirst",
            "format", "formatted",
            "concat", "substring", "trim", "strip",
            "toLowerCase", "toUpperCase",
            "append", "insert", "toString"
    );
    private static final Set<String> TAINT_PROPAGATOR_METHODS = Set.of(
            "replace", "replaceAll", "replaceFirst",
            "format", "formatted",
            "append"
    );
    private static final Pattern ASSIGNMENT_PATTERN = Pattern.compile(
            "^(\\w+)\\s*=\\s*(.+)$"
    );

    Map<String, TaintSummary> summarizeAll(List<MethodNode> methods) {
        Map<String, TaintSummary> result = new LinkedHashMap<>();
        for (MethodNode method : methods) {
            result.put(method.id(), summarize(method));
        }
        return Map.copyOf(result);
    }

    TaintSummary summarize(MethodNode method) {
        // 参数名 → 参数索引的映射
        Map<String, Integer> paramIndices = new LinkedHashMap<>();
        for (int i = 0; i < method.parameterNames().size(); i++) {
            paramIndices.put(method.parameterNames().get(i), i);
        }

        // 变量 → 其携带的参数污点索引集合
        // 初始时每个参数变量被自身参数索引污染
        Map<String, Set<Integer>> variableTaint = new LinkedHashMap<>();
        for (var entry : paramIndices.entrySet()) {
            variableTaint.computeIfAbsent(entry.getKey(), k -> new HashSet<>())
                    .add(entry.getValue());
        }

        List<TaintFlow> flows = new ArrayList<>();
        boolean hasStringManip = false;
        boolean hasTaintProp = false;

        for (CallSite call : method.calls()) {
            // 检查此调用的每个参数是否引用了被污染的变量
            String expression = call.expression() != null ? call.expression() : "";

            for (int argIdx = 0; argIdx < call.argumentTypes().size(); argIdx++) {
                // 从表达式中提取参数引用的变量名
                // 这里用简化方式：检查表达式中是否包含被污染变量名
                for (var taintEntry : variableTaint.entrySet()) {
                    String varName = taintEntry.getKey();
                    if (expressionReferencesVariable(expression, varName, call.methodName(), argIdx)) {
                        for (int paramIdx : taintEntry.getValue()) {
                            String propType = inferPropagationType(call.methodName());
                            flows.add(new TaintFlow(
                                    paramIdx,
                                    call.methodName(),
                                    call.receiver(),
                                    argIdx,
                                    propType
                            ));
                        }
                    }
                }
            }

            // 字符串操作的污点传播
            if (STRING_PROPAGATORS.contains(call.methodName())) {
                hasStringManip = true;
                // 如果 receiver 是被污染变量，结果也被污染
                String receiver = call.receiver();
                if (receiver != null) {
                    String rootVar = receiver.split("[.\\[(]", 2)[0];
                    Set<Integer> receiverTaint = variableTaint.get(rootVar);
                    if (receiverTaint != null && !receiverTaint.isEmpty()) {
                        hasTaintProp = true;
                    }
                }
                // 如果参数中有被污染的变量，结果也被污染
                if (TAINT_PROPAGATOR_METHODS.contains(call.methodName())) {
                    for (var taintEntry : variableTaint.entrySet()) {
                        if (expression.contains(taintEntry.getKey())
                                && !taintEntry.getValue().isEmpty()) {
                            hasTaintProp = true;
                            // 将调用 receiver 变量也标记为被污染
                            if (receiver != null && !receiver.isBlank()) {
                                String rootReceiver = receiver.split("[.\\[(]", 2)[0];
                                variableTaint.computeIfAbsent(rootReceiver, k -> new HashSet<>())
                                        .addAll(taintEntry.getValue());
                            }
                        }
                    }
                }
            }

            // 对于赋值模式（如 String result = someCall(...)），传播污点到赋值目标
            // 这需要通过变量类型的变化来推断
            // 简化处理：如果调用的某个参数被污染，且返回值被赋给某变量，
            // 则该变量继承污点
        }

        // 检查哪些参数可能到达 return
        Set<Integer> paramsThatReachReturn = new HashSet<>();
        String signature = method.signature() != null ? method.signature() : "";
        for (var entry : variableTaint.entrySet()) {
            if (!entry.getValue().isEmpty() && signature.contains(entry.getKey())) {
                paramsThatReachReturn.addAll(entry.getValue());
            }
        }

        return new TaintSummary(
                method.id(),
                List.copyOf(flows),
                Set.copyOf(paramsThatReachReturn),
                hasStringManip,
                hasTaintProp
        );
    }

    private boolean expressionReferencesVariable(
            String expression,
            String varName,
            String methodName,
            int argIdx
    ) {
        if (expression == null || expression.isBlank()) {
            return false;
        }
        // 简化的引用检测：检查变量名是否作为独立标识符出现在表达式中
        // 使用单词边界匹配避免误匹配（如 "name" 不应匹配 "fileName"）
        return Pattern.compile("\\b" + Pattern.quote(varName) + "\\b")
                .matcher(expression)
                .find();
    }

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
}
```

**重要说明**：
- 这是一个**轻量级**方法内分析，不使用 AST——直接基于已有的 MethodNode 数据（calls、variableTypes、parameterNames）
- 精度有限但足够用：主要目的是检测 `paramX → replace()/format() → callY(result)` 这类明显的污点传播链
- 所有方法的分析独立进行，无跨方法依赖

---

## 修改 6：新增 TaintFlowVerifier

**新文件**：`src/main/java/com/huawei/audit/analysis/impl/TaintFlowVerifier.java`

此类接受候选路径列表和污点摘要映射，对每条候选路径验证污点是否从入口参数流到 sink。

```java
package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallEdge;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.CandidatePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.EntryPoint;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodStep;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.TaintFlow;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.TaintSummary;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class TaintFlowVerifier {

    List<CandidatePath> verify(
            List<CandidatePath> candidates,
            Map<String, TaintSummary> summaries
    ) {
        List<CandidatePath> result = new ArrayList<>(candidates.size());
        for (CandidatePath candidate : candidates) {
            VerificationResult verification = verifyPath(candidate, summaries);
            result.add(new CandidatePath(
                    candidate.id(),
                    candidate.entryPoint(),
                    candidate.sink(),
                    candidate.methodPath(),
                    candidate.callEdges(),
                    candidate.staticConfidence(),
                    candidate.callDepth(),
                    candidate.reviewStatus(),
                    verification.confidence(),
                    verification.trace()
            ));
        }
        return List.copyOf(result);
    }

    private VerificationResult verifyPath(
            CandidatePath candidate,
            Map<String, TaintSummary> summaries
    ) {
        List<MethodStep> steps = candidate.methodPath();
        List<CallEdge> edges = candidate.callEdges();
        List<String> trace = new ArrayList<>();

        if (steps.isEmpty()) {
            return new VerificationResult("NONE", trace);
        }

        // 入口方法的所有参数都是潜在污点源
        String entryMethodId = steps.getFirst().methodId();
        TaintSummary entrySummary = summaries.get(entryMethodId);
        MethodStep entryStep = steps.getFirst();

        // 当前在各方法中被污染的参数索引集合
        Set<Integer> currentTaintedParams = new HashSet<>();

        // 入口点：HTTP 参数都是污点源
        if (entrySummary != null) {
            for (int i = 0; i < entrySummary.parameterFlows().size() + 1; i++) {
                currentTaintedParams.add(i);
            }
        }
        // 保守假设：入口方法的所有参数都被污染
        currentTaintedParams.add(0);
        currentTaintedParams.add(1);
        currentTaintedParams.add(2);
        currentTaintedParams.add(3);

        trace.add("Entry: " + entryStep.className() + "." + entryStep.methodName()
                + " — all HTTP parameters are taint sources");

        boolean taintReachesSink = false;
        boolean hasStringPropagation = false;
        int taintedEdges = 0;

        // 沿路径逐步检查污点传播
        for (int edgeIdx = 0; edgeIdx < edges.size(); edgeIdx++) {
            CallEdge edge = edges.get(edgeIdx);
            String fromMethodId = edge.fromMethodId();
            String toMethodId = edge.toMethodId();

            TaintSummary fromSummary = summaries.get(fromMethodId);
            if (fromSummary == null) {
                trace.add("Step " + (edgeIdx + 1) + ": " + abbreviateMethodId(fromMethodId)
                        + " → " + abbreviateMethodId(toMethodId)
                        + " [no taint summary, assumed propagated]");
                continue;
            }

            // 检查从当前方法到下一个方法的污点流
            boolean edgeTainted = false;
            Set<Integer> nextTaintedParams = new HashSet<>();

            for (TaintFlow flow : fromSummary.parameterFlows()) {
                if (currentTaintedParams.contains(flow.sourceParamIndex())) {
                    edgeTainted = true;
                    nextTaintedParams.add(flow.targetArgIndex());

                    String propDesc = switch (flow.propagationType()) {
                        case "replace" -> "via String.replace() template substitution";
                        case "format" -> "via String.format()";
                        case "concatenation" -> "via string concatenation";
                        case "constructor-arg" -> "via constructor parameter";
                        default -> "via direct argument passing";
                    };

                    if ("replace".equals(flow.propagationType())
                            || "format".equals(flow.propagationType())) {
                        hasStringPropagation = true;
                    }

                    trace.add("Step " + (edgeIdx + 1) + ": param[" + flow.sourceParamIndex()
                            + "] of " + abbreviateMethodId(fromMethodId)
                            + " → arg[" + flow.targetArgIndex() + "] of "
                            + flow.targetCallMethodName()
                            + " " + propDesc);
                }
            }

            if (edgeTainted) {
                taintedEdges++;
                currentTaintedParams = nextTaintedParams;
            } else {
                // 保守策略：如果没有明确的污点流信息，
                // 且方法有字符串操作，仍然假设可能传播
                if (fromSummary.hasTaintPropagation()) {
                    trace.add("Step " + (edgeIdx + 1) + ": "
                            + abbreviateMethodId(fromMethodId)
                            + " has taint propagation (replace/format), assumed flowing");
                    hasStringPropagation = true;
                } else {
                    trace.add("Step " + (edgeIdx + 1) + ": "
                            + abbreviateMethodId(fromMethodId)
                            + " → " + abbreviateMethodId(toMethodId)
                            + " [structural edge, no confirmed taint flow]");
                }
            }

            // 最后一步到达 sink 方法
            if (edgeIdx == edges.size() - 1) {
                TaintSummary sinkSummary = summaries.get(toMethodId);
                if (sinkSummary != null && sinkSummary.hasTaintPropagation()) {
                    taintReachesSink = true;
                    trace.add("Sink: " + abbreviateMethodId(toMethodId)
                            + " — tainted data reaches dangerous operation");
                } else if (!currentTaintedParams.isEmpty()) {
                    taintReachesSink = true;
                    trace.add("Sink: " + abbreviateMethodId(toMethodId)
                            + " — tainted parameters forwarded to sink method");
                }
            }
        }

        String confidence;
        if (taintReachesSink && hasStringPropagation) {
            confidence = "CONFIRMED";
        } else if (taintReachesSink || taintedEdges > edges.size() / 2) {
            confidence = "LIKELY";
        } else if (taintedEdges > 0) {
            confidence = "STRUCTURAL";
        } else {
            confidence = "STRUCTURAL";
        }

        return new VerificationResult(confidence, List.copyOf(trace));
    }

    private String abbreviateMethodId(String methodId) {
        int atIdx = methodId.indexOf('@');
        return atIdx > 0 ? methodId.substring(0, atIdx) : methodId;
    }

    private record VerificationResult(String confidence, List<String> trace) { }
}
```

---

## 修改 7：WhiteBoxAnalysisServiceImpl — 集成污点分析

**文件**：`src/main/java/com/huawei/audit/analysis/impl/WhiteBoxAnalysisServiceImpl.java`

在 `analyze()` 方法中，在候选路径查找之后、返回结果之前，插入污点分析步骤。

### 7.1 添加字段

在类的字段声明中添加：
```java
private final MethodTaintSummarizer taintSummarizer;
private final TaintFlowVerifier taintFlowVerifier;
```

在构造函数中初始化：
```java
this.taintSummarizer = new MethodTaintSummarizer();
this.taintFlowVerifier = new TaintFlowVerifier();
```

### 7.2 在 analyze() 中集成

在候选路径查找之后（`candidatePathFinder.find(...)` 调用之后），添加污点分析：

找到：
```java
List<CandidatePath> candidates = candidatePathFinder.find(
        entryPoints,
        finalIndex,
        callGraph
);
```

在其后追加：
```java
// 方法级污点分析
Map<String, TaintSummary> taintSummaries = taintSummarizer.summarizeAll(finalIndex.methods());
List<CandidatePath> taintVerifiedCandidates = taintFlowVerifier.verify(candidates, taintSummaries);
```

然后将后续所有使用 `candidates` 的地方替换为 `taintVerifiedCandidates`。具体来说：

将：
```java
List<StorageWritePath> writePaths = storageWritePathFinder.find(
        entryPoints,
        finalIndex,
        callGraph
);
List<StoredCandidate> storedCandidates =
        storedCandidateCorrelator.correlate(
                writePaths,
                candidates,
                finalIndex
        );
return new AnalysisResult(
        entryPoints,
        finalIndex.sinks(),
        candidates,
        // ...
);
```

改为：
```java
List<StorageWritePath> writePaths = storageWritePathFinder.find(
        entryPoints,
        finalIndex,
        callGraph
);
List<StoredCandidate> storedCandidates =
        storedCandidateCorrelator.correlate(
                writePaths,
                taintVerifiedCandidates,
                finalIndex
        );
return new AnalysisResult(
        entryPoints,
        finalIndex.sinks(),
        taintVerifiedCandidates,
        finalIndex.storageAccesses(),
        storedCandidates,
        callGraph.unresolvedCalls(),
        finalIndex.parseErrors(),
        coverageCalculator.calculate(
                sourceRoot,
                finalIndex,
                callGraph,
                entryPoints,
                taintVerifiedCandidates,
                storedCandidates,
                extraRules.size(),
                llmReviewedSinks.size()
        ),
        Map.copyOf(taintSummaries)   // ← 新增参数
);
```

### 7.3 添加 import

在文件头部添加：
```java
import com.huawei.audit.analysis.WhiteBoxAnalysisService.TaintSummary;
```

---

## 修改 8：更新现有测试

### 8.1 所有构造 MethodNode 的地方需要加 parameterNames 参数

MethodNode record 增加了 `parameterNames` 字段（在 `parameterCount` 之后），所有测试中构造 MethodNode 的地方需要在第 4 个参数（parameterCount）后面加入 `List.of("param1", "param2", ...)` 或 `List.of()`。

搜索项目中所有 `new MethodNode(` 的位置并逐一修改。

### 8.2 所有构造 CandidatePath 的地方需要加 taintConfidence 和 taintTrace 参数

CandidatePath record 增加了两个尾部字段。所有测试中构造 CandidatePath 的地方，在末尾加上 `"PENDING", List.of()`。

搜索项目中所有 `new CandidatePath(` 的位置并逐一修改。

### 8.3 所有构造 AnalysisResult 的地方需要加 taintSummaries 参数

AnalysisResult 增加了 `taintSummaries` 字段。在末尾加上 `Map.of()`。

---

## 修改 9：新增测试用例

### 9.1 WhiteBoxAnalysisServiceTest — 模板替换命令注入测试

**文件**：`src/test/java/com/huawei/audit/analysis/WhiteBoxAnalysisServiceTest.java`

在文件末尾（最后一个 `}` 之前）追加以下测试方法：

```java
@Test
void detectsTemplateSubstitutionCommandInjectionThroughAsyncExecution()
        throws Exception {
    // 模拟 createCollectionTask → extensionParams → TaskUtil.generateQuery()
    // → String.replace() → bash -c 的调用链

    // 入口控制器
    Files.writeString(tempDir.resolve("CollectionController.java"), """
            import org.springframework.web.bind.annotation.*;
            import java.util.Map;

            @RestController
            class CollectionController {
                private TaskCreator creator;

                @PostMapping("/task")
                void createTask(@RequestBody TaskRequest request) {
                    creator.createMainTask(request);
                }
            }
            """);

    // 任务创建器 - 创建执行器并提交
    Files.writeString(tempDir.resolve("TaskCreator.java"), """
            import java.util.concurrent.ExecutorService;

            class TaskCreator {
                private ExecutorService pool;

                void createMainTask(TaskRequest request) {
                    TaskExecutor executor = new TaskExecutor(
                            request.getExtensionParams()
                    );
                    pool.submit(executor);
                }
            }
            """);

    // 异步执行器
    Files.writeString(tempDir.resolve("TaskExecutor.java"), """
            import java.util.Map;

            class TaskExecutor implements Runnable {
                private Map<String, String> extensionParams;

                TaskExecutor(Map<String, String> extensionParams) {
                    this.extensionParams = extensionParams;
                }

                public void run() {
                    executeCollection();
                }

                private void executeCollection() {
                    CollectorStrategy strategy = new RestCollectorStrategy();
                    strategy.collect(extensionParams);
                }
            }
            """);

    // 策略接口
    Files.writeString(tempDir.resolve("CollectorStrategy.java"), """
            import java.util.Map;

            interface CollectorStrategy {
                void collect(Map<String, String> params);
            }
            """);

    // REST 采集策略 - 包含模板替换 + 命令执行
    Files.writeString(tempDir.resolve("RestCollectorStrategy.java"), """
            import java.util.Map;

            class RestCollectorStrategy implements CollectorStrategy {
                public void collect(Map<String, String> params) {
                    String query = "hgetAll DeviceRecord:${dn}";
                    String replaced = QueryUtil.generateQuery(query, params);
                    executeCommand(replaced);
                }

                private void executeCommand(String command) {
                    try {
                        String cmd = "source /opt/profile.sh && tool --query \\"" + command + "\\"";
                        new ProcessBuilder("/bin/bash", "-c", cmd).start();
                    } catch (Exception ignored) {}
                }
            }
            """);

    // 查询生成工具 - 不安全的模板替换
    Files.writeString(tempDir.resolve("QueryUtil.java"), """
            import java.util.Map;

            class QueryUtil {
                static String generateQuery(String template, Map<String, String> params) {
                    String result = template;
                    for (Map.Entry<String, String> entry : params.entrySet()) {
                        result = result.replace("${" + entry.getKey() + "}", entry.getValue());
                    }
                    return result;
                }
            }
            """);

    // 请求对象
    Files.writeString(tempDir.resolve("TaskRequest.java"), """
            import java.util.Map;

            class TaskRequest {
                Map<String, String> extensionParams;
                Map<String, String> getExtensionParams() { return extensionParams; }
            }
            """);

    var result = new WhiteBoxAnalysisServiceImpl(
            List.of(new HttpEndpointScanner())
    ).analyze(tempDir, List.of(), null, "claude");

    // 验证：必须找到从 /task 入口到 ProcessBuilder sink 的候选路径
    assertThat(result.candidatePaths())
            .filteredOn(c -> c.entryPoint().path().equals("/task"))
            .filteredOn(c -> c.sink().category().equals("COMMAND_EXECUTION"))
            .isNotEmpty()
            .anySatisfy(candidate -> {
                // 路径应该穿过异步执行和策略模式
                assertThat(candidate.methodPath())
                        .extracting(step -> step.className())
                        .contains("CollectionController", "RestCollectorStrategy");
                // 污点追踪应标记为已确认或可能
                assertThat(candidate.taintConfidence())
                        .isIn("CONFIRMED", "LIKELY");
            });

    // 验证：污点摘要应包含 RestCollectorStrategy 的 replace 传播
    assertThat(result.taintSummaries())
            .anySatisfy((methodId, summary) -> {
                if (methodId.contains("RestCollectorStrategy#collect")) {
                    assertThat(summary.hasTaintPropagation()).isTrue();
                }
            });
}
```

### 9.2 MethodTaintSummarizerTest

**新文件**：`src/test/java/com/huawei/audit/analysis/impl/MethodTaintSummarizerTest.java`

```java
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
```

---

## 修改 10：CoverageCalculator 适配

**文件**：`src/main/java/com/huawei/audit/analysis/impl/CoverageCalculator.java`

Coverage record 不需要改动（污点信息通过 CandidatePath 的 taintConfidence 字段暴露），但如果你希望在 Coverage 中增加污点统计，可以添加：

```java
long taintConfirmedCandidates  // taintConfidence == "CONFIRMED" 的候选路径数
long taintLikelyCandidates     // taintConfidence == "LIKELY" 的候选路径数
```

这是可选的增强，不是必须的。

---

## 修改要点总结

### 必须修改的文件（按依赖顺序）

1. **WhiteBoxAnalysisService.java** — 修改 MethodNode、CandidatePath、AnalysisResult record，新增 TaintSummary、TaintFlow record
2. **CompilationUnitIndexer.java** — 收集 parameterNames，传给 MethodNode
3. **MethodBodyIndexer.java** — visitNewClass 中添加构造函数 CallSite
4. **CandidatePathFinder.java** — MAX_PATH_DEPTH 改为 20，CandidatePath 构造增加两个字段
5. **MethodTaintSummarizer.java** — 新增文件
6. **TaintFlowVerifier.java** — 新增文件
7. **WhiteBoxAnalysisServiceImpl.java** — 集成污点分析

### 必须修改的测试文件

搜索所有 `new MethodNode(` 和 `new CandidatePath(` 和 `new AnalysisResult(` 的位置，为它们添加新字段值。

主要涉及：
- `WhiteBoxAnalysisServiceTest.java` — 新增模板替换测试
- `JavaSourceIndexerTest.java` — 适配 MethodNode 新字段（build 方法返回的 SourceIndex 中的 MethodNode 会自动包含新字段，但如果测试中手动构造了 MethodNode 则需要修改）
- `EvidencePreparationServiceTest.java` — 适配 AnalysisResult 新字段
- `EvidencePackagePolicyTest.java` — 适配 CandidatePath 新字段
- `SupervisorAgentTest.java` — 如果涉及 CandidatePath 构造
- `IntelligentAuditGraphTest.java` — 如果涉及 AnalysisResult

### 编译验证

修改完成后运行：
```bash
./mvnw compile test
```

确保所有 49+ 个测试通过。

---

## 验证标准

修改完成后，系统应该能够：

1. **构造函数调用追踪**：`new CollectionTaskExecutor(scenarios)` 应产生一条到 `CollectionTaskExecutor.<init>` 的调用边
2. **深层路径发现**：从 `createCollectionTask` 到 `ProcessBuilder.start()` 的 13-15 步路径应被发现
3. **模板替换污点追踪**：`String.replace("${key}", userInput)` 应被标记为污点传播器
4. **污点置信度**：包含 `replace` 传播的候选路径应获得 `CONFIRMED` 或 `LIKELY` 的 `taintConfidence`
5. **测试用例**：`detectsTemplateSubstitutionCommandInjectionThroughAsyncExecution` 测试通过

这些修改将使系统能够检测到类似 DPFaultHorizonService 中 `createCollectionTask → extensionParams → TaskUtil.generateQuery() → String.replace() → bash -c` 这类深层模板替换命令注入链。
