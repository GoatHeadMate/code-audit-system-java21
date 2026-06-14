---
description: 运行项目测试并验证编译
---

运行以下命令验证项目状态：

```bash
mvn test 2>&1
```

如果测试失败，分析失败原因并报告。如果需要运行特定测试类，使用：

```bash
mvn test -pl . -Dtest="$ARGUMENTS" -DfailIfNoTests=false
```

最后运行编译检查：

```bash
mvn compile -q 2>&1
```

报告测试结果和编译状态。
