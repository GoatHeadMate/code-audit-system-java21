---
description: 理解项目结构和当前状态
---

执行以下步骤来理解项目：

1. 读取项目记忆文件：`C:\Users\23690\.local\share\mimocode\memory\projects\52db8fe4-027c-4c60-ad7f-c575630bb0f2\MEMORY.md`

2. 检查当前会话的 checkpoint 文件（如果存在）

3. 读取项目根目录的 `pom.xml` 了解依赖

4. 扫描 `src/main/java/com/huawei/audit/` 目录结构

5. 检查当前 git 分支和状态：
   ```bash
   git status --short
   git branch --show-current
   ```

6. 运行测试验证当前状态：
   ```bash
   mvn test -q 2>&1
   ```

7. 总结：
   - 项目目标和架构
   - 当前工作分支
   - 最近的修改
   - 测试状态
   - 待解决的问题（如果有）
