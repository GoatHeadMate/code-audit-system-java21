# JavaParser 迁移计划

把白盒分析的「索引 / 调用图层」从 JDK Compiler API（`com.sun.source`）迁移到
**JavaParser + JavaSymbolSolver**，并顺带把入口扫描层从正则改为 AST。

> 状态：进行中 ｜ 分支：`feat/javaparser-migration` ｜ 起始：2026-06-17

---

## 1. 背景与目标

**现状**
- `analysis/impl` 的源码索引基于 JDK 编译器 `task.parse()`（仅语法解析、不做类型归约），
  类型信息全是字符串启发式（`simpleName` + `variableTypes` map）。
- `CallGraphBuilder` 靠名字 + arity + 首字母大写猜类型等启发式连边。
- 入口扫描层（`source/`）是正则逐行解析，存在已知漏报缺陷
  （相对路径被丢弃、注释里的 `class/interface/record` 污染 className、内部类串味）。

**目标**
- 用 JavaParser 替换解析引擎；用 JavaSymbolSolver 提供真实类型解析，提升调用图 / 污点精度。
- 修复入口扫描层的已知缺陷。

---

## 2. 前提确认（已验证 2026-06-17）

- 工具链：Maven 3.8.9 + Adoptium JDK 21。
- 仓库 / 镜像：localRepository = `E:\Softwares\apache-maven-3.8.9\repo`，
  mirror = 阿里云公共仓库（可联网）。
- 依赖可用：`com.github.javaparser:javaparser-symbol-solver-core:3.26.2`
  已解析（BUILD SUCCESS，jar 已落 localRepo）。
- 耦合面：整个 `analysis/impl`（约 3944 行，25 文件）中**仅 3 个文件**直接依赖
  `com.sun.source`：
  - `JavaSourceIndexer.java`（143）
  - `CompilationUnitIndexer.java`（248）
  - `MethodBodyIndexer.java`（227）

  其余文件均消费 `WhiteBoxAnalysisService` 的 record 模型。

---

## 3. 设计约束（不可破坏）

- **对外契约不变**：`WhiteBoxAnalysisService` 的 records
  （`MethodNode`/`Sink`/`CallSite`/`StorageAccess`/`AnalysisResult` 等）保持结构不变；
  迁移只换内部实现，下游 20+ 文件（`CallGraphBuilder`/`DangerousSinkClassifier`/
  taint/`CandidatePathFinder`…）复用。
- **SymbolSolver 容错**：解析失败必须回退现有字符串启发式，**绝不向外抛异常**。
- **无 classpath 现实**：SymbolSolver 仅能精确解析 JDK（Reflection）+ 项目自身源码
  （JavaParserTypeSolver）；第三方 / 框架类型仍 UNSOLVED，继续走启发式。
- **每阶段独立可编译、可测试、可提交**（中文 commit，遵守项目 git 规范）。

---

## 4. 阶段拆分

### 阶段 1 — 引入依赖
- 改动：`pom.xml` 加 `javaparser-symbol-solver-core` 3.26.2。
- 验证：`mvn -q compile`。
- 提交：`build: 引入 JavaParser + SymbolSolver 依赖`

### 阶段 2 — 纯 AST 等价替换 3 个 indexer（暂不启用 SymbolSolver）
- 改动：
  - `JavaSourceIndexer`：`JavaParser` 解析 .java → `CompilationUnit`；保留批处理与
    parseErrors（收集 `ParseProblemException` / `Problem`）。
  - `CompilationUnitIndexer`：`TreePathScanner` → `VoidVisitorAdapter<Void>`；
    `visitClass`→`visit(ClassOrInterfaceDeclaration)`，
    `visitMethod`→`visit(MethodDeclaration)`；行号 `node.getBegin()`；
    sourceText 用 range / `toString()`。
  - `MethodBodyIndexer`：`visitMethodInvocation`→`visit(MethodCallExpr)`，
    `visitNewClass`→`visit(ObjectCreationExpr)`，
    `visitMemberReference`→`visit(MethodReferenceExpr)`，
    `visitVariable`→`visit(VariableDeclarator)`。
  - 类型仍用现有字符串启发式，保证语义等价。
- 验证：现有测试全过（必要时按 javac↔JavaParser 表述差异微调断言）。
- 提交：`refactor: 索引层从 JDK Compiler 迁移到 JavaParser（纯 AST 等价）`

### 阶段 3 — 接入 SymbolSolver 精确化类型
- 改动：`CombinedTypeSolver`（ReflectionTypeSolver + JavaParserTypeSolver(sourceRoot)）；
  `calculateResolvedType()` 精确填 receiverType / argumentTypes / variableTypes，
  失败回退启发式；全局 catch 容错。
- 验证：`CallGraphBuilder` 命中率↑、`unresolvedCalls`↓（coverage 对比）；测试全过。
- 提交：`feat: 接入 JavaSymbolSolver 精确解析类型（失败回退启发式）`

### 阶段 4 — （可选）CallGraphBuilder 精确连边
- 改动：`MethodCallExpr.resolve()` 拿声明类型 + 签名直接连边
  （resolution="symbol-solver"），启发式兜底。
- 提交：`feat: CallGraphBuilder 增加 SymbolSolver 精确连边通道`

### 阶段 5 — 入口层 discoverer 迁 JavaParser + 修已知 bug
- 改动：`HttpEndpointScanner` / `HttpAnnotationParser` 改 AST 提取注解；
  修相对路径丢弃、注释污染 className、内部类串味。
- 验证：扩 `HttpEndpointScannerTest` 回归用例（相对路径 / 注释 / 内部类 / 常量路径 /
  Feign 接口）。
- 提交：`refactor: 入口扫描层迁移到 JavaParser 并修复路径/类名解析缺陷`

---

## 5. 风险与缓解

| 风险 | 缓解 |
|---|---|
| SymbolSolver 性能（慢一个数量级） | 阶段 3 单独验证耗时；必要时只对 sink 相关表达式解析；保留 analysisSlot 单例锁 + 30m 超时 |
| 无 classpath → 第三方 UNSOLVED | 回退启发式；收益定位为「项目内部源码精度」，不承诺框架边界 |
| 阶段 2 中途不可编译 | 阶段内一次性迁完 3 文件再跑测试 |
| 测试精确断言因 AST 差异失败 | 视为表述差异更新断言，非回归 |

---

## 6. 回滚策略

每阶段独立 commit；如某阶段验证不通过，`git revert` 该阶段提交即可回到上一个可用状态。
阶段 1（加依赖）与阶段 5（入口层）与主线解耦，可独立回滚。

---

## 7. 进度

- [ ] 阶段 1 引入依赖
- [ ] 阶段 2 纯 AST 等价替换
- [ ] 阶段 3 接入 SymbolSolver
- [ ] 阶段 4 （可选）精确连边
- [ ] 阶段 5 入口层迁移 + 修 bug
