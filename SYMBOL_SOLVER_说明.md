# JavaParser SymbolSolver 原理与本项目接入说明

> 适用分支:`master`(JavaParser 版白盒管线)
> 相关开关:`-Daudit.symbol-solver=true` / 环境变量 `SYMBOL_SOLVER_ENABLED=true`(默认 **关**)
> 实测影响:同一项目单接口扫描,`candidate_paths` 从 **2 → 200**,`stored_candidates` 从 **0 → 88**(详见文末)

---

## 1. 它要解决的核心问题:调用点的"接收者类型"

白盒管线要把"入口方法"沿调用链连到"危险 sink",必须知道**每个方法调用到底调的是哪个类的哪个方法**。例如:

```java
delegate.executeCmdCollectionTask(context, params);
```

要把这条边连到 `ScenariosCollectionServiceDelegateImpl.executeCmdCollectionTask`,就必须先知道 `delegate` 这个变量的**静态类型**是 `ScenariosCollectionServiceDelegate`(接口),再找它的实现类。这个"由表达式推出类型"的能力,就是 **SymbolSolver(符号/类型解析)**。

纯 AST(JavaParser 默认模式)只能看到 `delegate` 这个**词法 token**,看不出它的类型——这就是 `receiverType` 解析问题。

---

## 2. 本项目的两层架构:词法启发式(默认) + SymbolSolver(opt-in)

调用点类型解析在 [`MethodBodyIndexer.visit(MethodCallExpr)`](src/main/java/com/huawei/audit/analysis/impl/MethodBodyIndexer.java) 里,按"**先精确、后启发**"的顺序取 `receiverType`:

```java
String receiver = tree.getScope().map(Object::toString).orElse("");
String receiverType = resolveScopeType(tree)          // ① SymbolSolver 精确解析(开启时)
        .orElseGet(() -> receiverType(receiver));     // ② 词法启发式回退(永远兜底)
```

### ② 词法启发式(默认,SymbolSolver 关闭时唯一手段)

`receiverType(String receiver)`(同文件)的逻辑:

```java
String root = normalized.split("[.\\[(]", 2)[0];        // 取调用接收者的根 token
String variableType = variableTypes.get(root);          // 查同方法内的局部变量/字段声明表
return variableType != null
        ? variableType
        : AnalysisTextUtils.startsUppercase(root) ? root : "";  // 首字母大写当类名,否则放弃
```

它只能靠三招猜:
- 在**当前方法内**声明过的变量(`variableTypes` 表,来自 `Foo foo = ...` 这种就近声明);
- 接收者首字母大写 → 当作静态类名(`Runtime.getRuntime()`);
- 其余一律放弃(返回空)。

跨方法、跨类、经过返回值/字段/泛型传递的类型,它**全都猜不到**。

### ① SymbolSolver 精确解析(开启时)

`resolveScopeType` 与 `expressionType`(同文件)调用 JavaParser 的类型推断 API:

```java
private Optional<String> resolveScopeType(MethodCallExpr call) {
    if (!symbolSolverEnabled) {
        return Optional.empty();                       // 关闭时直接跳过,走词法回退
    }
    return call.getScope().flatMap(scope -> {
        try {
            String resolved = AnalysisTextUtils.simpleName(
                    scope.calculateResolvedType().describe());   // ★ 真正的类型解析
            return resolved.isBlank() ? Optional.empty() : Optional.of(resolved);
        } catch (Throwable ignored) {
            return Optional.empty();                    // 解析失败(如第三方类型)静默回退
        }
    });
}
```

`scope.calculateResolvedType()` 会让 SymbolSolver 沿"声明 → 类型 → 继承/实现链"真正算出表达式的类型,`.describe()` 得到全限定名,再 `simpleName` 取简单名。失败就吞掉异常回退到词法启发式——所以**开启 SymbolSolver 永远不会比关闭更差**,只会更准。

参数类型 `expressionType` 同理(先 `calculateResolvedType` 再回退到 `变量表 / new 表达式`)。

---

## 3. SymbolSolver 是怎么"算"出类型的

SymbolSolver 需要一个 **TypeSolver**(类型来源)才能工作。本项目在 [`JavaSourceIndexer`](src/main/java/com/huawei/audit/analysis/impl/JavaSourceIndexer.java) 里构建并挂载:

```java
boolean symbolSolverEnabled = symbolSolverEnabled();
ParserConfiguration configuration = new ParserConfiguration()
        .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
if (symbolSolverEnabled) {
    configuration.setSymbolResolver(
            new JavaSymbolSolver(buildTypeSolver(sourceRoot, sourceFiles)));
}
JavaParser parser = new JavaParser(configuration);
```

### TypeSolver 的组成

```java
private TypeSolver buildTypeSolver(Path sourceRoot, List<Path> files) {
    CombinedTypeSolver combined = new CombinedTypeSolver();
    combined.add(new ReflectionTypeSolver());           // ① JDK 内置类型(java.*,通过反射)
    for (Path root : detectSourceRoots(sourceRoot, files)) {
        combined.add(new JavaParserTypeSolver(root));   // ② 项目源码类型(逐个源码根解析)
    }
    return combined;
}
```

- **`ReflectionTypeSolver`**:解析 JDK 标准库类型(`String`、`Runtime`、`ProcessBuilder`…),靠运行时反射,无需源码。
- **`JavaParserTypeSolver`**:解析**项目自己的源码类型**,对每个源码根目录建立"包名 → .java 文件"的索引,按需 parse 出类型。
- **`CombinedTypeSolver`**:按顺序串联,谁先解出算谁的。

> ⚠️ 注意:这里**没有** `JarTypeSolver` / classpath solver。也就是说,**第三方库(Spring、Jackson、Huawei 内部 jar 等)的类型解析不了**——这正是后文 `unresolved_calls` 几乎不降的根因。

### 源码根的自动推断 `detectSourceRoots`

`JavaParserTypeSolver` 要的是"包根目录"(即 `com/...` 的上一级),而上传的项目布局五花八门(Maven / Gradle / 反编译平铺)。本项目不假设构建工具,而是**用每个文件声明的 `package` 反推根**:

```java
String declaredPackage = readPackage(file);             // 读文件头部 package 语句
Path root = directory;
int segments = declaredPackage.split("\\.").length;     // 包名有几段
for (int i = 0; i < segments && root != null; i++) {
    root = root.getParent();                            // 从文件目录上溯同样多层 = 源码根
}
roots.add(root != null ? root : directory);
```

例:文件 `.../huawei_jar_src/com/huawei/neteco/dpfault/service/CollectionTask.java` 声明 `package com.huawei.neteco.dpfault.service;`(5 段),从 `service/` 上溯 5 层 → 源码根 `.../huawei_jar_src/`。这样任意布局都能正确建根,无需 `pom.xml`/`build.gradle`。

---

## 4. 类型解析如何转化为"调用链"

`receiverType` 解析出来后,流向 [`CallGraphBuilder.resolveTargets`](src/main/java/com/huawei/audit/analysis/impl/CallGraphBuilder.java),它用 `receiverType` 去 `methodsByClassAndName` 索引里找目标方法,并顺接口实现链:

```java
if (receiverType != null && !receiverType.isBlank()) {
    addClassTargets(targets, index, receiverType, call, "receiver-type");
    for (String impl : implementations.getOrDefault(
            simpleName(receiverType), Set.of())) {       // 接口 → 实现类
        addClassTargets(targets, index, impl, call, "interface-implementation");
    }
}
```

- `receiverType` 准确 → 解析出 `receiver-type` / `interface-implementation` 类型的边(`CandidatePathFinder` 视其为 **HIGH** 置信);
- `receiverType` 为空 → 退化到 `static-class-name` / `field-name-type` / `unique-method-name-untyped` 等弱启发式,甚至直接进 `unresolved`。

最后 [`CandidatePathFinder`](src/main/java/com/huawei/audit/analysis/impl/CandidatePathFinder.java) 在这张调用图上做"入口 → sink"的有界 BFS(`ReverseReachability` 先算每个方法到 sink 的距离剪枝),产出 `candidate_paths`。**调用图越密 → 能连通的入口→sink 链越多。**

---

## 5. 为什么 `unresolved_calls` 几乎没降,`candidate_paths` 却暴涨

实测(同一项目、同样只扫 cmd 接口):

| 指标 | SymbolSolver 关 | SymbolSolver 开 | 变化 |
|---|---|---|---|
| `candidate_paths` | 2 | 200 | **×100** |
| `stored_candidates` | 0 | 88 | 0 → 88 |
| `sinks` | 651 | 952 | +46% |
| `storage_accesses` | 577 | 680 | +18% |
| `unresolved_calls` | 37512 | 36106 | **−3.7%** |

**解读:**

1. **`unresolved_calls` 只降 3.7%** —— 因为 TypeSolver 没有 jar/classpath solver,3.6 万未解析调用绝大多数是**第三方库调用**,SymbolSolver 对它们无能为力。
2. **`candidate_paths` 却 ×100** —— 因为打通入口→sink 链**不需要解析全部调用,只需解析那条链上的内部边**。`Service → delegate(接口) → DelegateImpl → CollectionTask → ProcessBuilder.start()` 全是**项目内部类型**,SymbolSolver 正好能解出(尤其是接口→实现这一步,词法启发式做不到)。少量但关键的内部边补全,就把链路从"几乎为空(2)"打通到"饱和(200)"。
3. **`sinks` 651→952** —— 调用图变密后,`TransitiveSinkResolver` 能沿更多已解析的边传播 sink 分类,识别出更多传递性 sink。

**一句话:** SymbolSolver 在本项目里基本修好了"静态数据链路丢失"问题,代价是只对**项目内部类型**有效;要再压低 `unresolved_calls`,得额外加 `JarTypeSolver` 把依赖 jar 喂进 TypeSolver。

---

## 6. 取舍与开关

SymbolSolver **慢一个数量级**(`JavaSourceIndexer` 注释原话:"order-of-magnitude slower"),因为每个调用点都要做一次类型推断。因此默认关闭,按场景开启:

| 场景 | 建议 | 理由 |
|---|---|---|
| 单接口/定向扫描 | 关 | LLM(supervisor)读码就能追出链路,静态链路收益不明显,不值得变慢 |
| 全量/广范围扫描 | 开 | 静态 `candidate_paths` 是给 LLM 喂种子的召回主力,2→200 的差距直接转化成召回率 |

### 开启方式

| 方式 | 写法 |
|---|---|
| JVM 系统属性(优先) | `-Daudit.symbol-solver=true` |
| 环境变量 | `SYMBOL_SOLVER_ENABLED=true` |
| `mvnw spring-boot:run` | 在 `spring-boot-maven-plugin` 的 `<jvmArguments>` 里加上 `-Daudit.symbol-solver=true` |
| IntelliJ IDEA | Run 配置 → Modify options → Add VM options → 填 `-Daudit.symbol-solver=true`(**不是** "Active profiles" 框) |

判定逻辑见 [`JavaSourceIndexer.symbolSolverEnabled()`](src/main/java/com/huawei/audit/analysis/impl/JavaSourceIndexer.java):系统属性优先,其次读环境变量,默认 `false`。

### 后续可做(若要进一步降 `unresolved_calls`)

- 给 `buildTypeSolver` 增加 `JarTypeSolver`,把项目依赖 jar(及 Huawei 内部 jar)加入 TypeSolver,让第三方调用也可解析;
- 但需先解决依赖收集(`mvn dependency:copy-dependencies` 或读已上传的 jar),成本较高,按需评估。

---

## 7. 相关文件索引

| 文件 | 职责 |
|---|---|
| [`JavaSourceIndexer.java`](src/main/java/com/huawei/audit/analysis/impl/JavaSourceIndexer.java) | 构建 `TypeSolver`、挂载 `JavaSymbolSolver`、源码根推断、开关读取 |
| [`MethodBodyIndexer.java`](src/main/java/com/huawei/audit/analysis/impl/MethodBodyIndexer.java) | 调用点 `receiverType`/参数类型解析(SymbolSolver 精确 + 词法回退) |
| [`CallGraphBuilder.java`](src/main/java/com/huawei/audit/analysis/impl/CallGraphBuilder.java) | 用 `receiverType` 解析调用目标,建调用图边 |
| [`CandidatePathFinder.java`](src/main/java/com/huawei/audit/analysis/impl/CandidatePathFinder.java) | 调用图上做入口→sink 有界 BFS,产出 `candidate_paths` |
| [`TransitiveSinkResolver.java`](src/main/java/com/huawei/audit/analysis/impl/TransitiveSinkResolver.java) | 沿调用图传播 sink 分类 |
