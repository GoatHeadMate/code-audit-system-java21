/**
 * 检测调试/测试参数绕过认证的模式。
 *
 * 常见场景：
 *   - if ("true".equals(request.getParameter("debug"))) { // skip auth }
 *   - if (request.getParameter("admin") != null) { isAdmin = true; }
 *   - if ("1".equals(request.getHeader("X-Debug"))) { response.setStatus(200); return; }
 *
 * 这类代码通常是开发调试遗留，在生产环境造成未授权访问。
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

/** 可疑的调试/旁路参数名（不区分大小写匹配） */
bindingset[name]
predicate isDebugParamName(string name) {
  name.toLowerCase().regexpMatch(".*(debug|test|bypass|admin_key|skip_auth|no_auth|dev_mode|dev|backdoor|secret|master_key).*")
}

/** 从 HttpServletRequest 读取参数或 Header 的调用 */
class RequestParamAccess extends MethodCall {
  RequestParamAccess() {
    this.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("javax.servlet.http", "HttpServletRequest")
    and this.getMethod().getName() in [
      "getParameter", "getHeader", "getParameterValues", "getAttribute"
    ]
  }

  /** 返回参数名字面量（若可获取） */
  string getParamName() {
    result = this.getArgument(0).(StringLiteral).getValue()
  }
}

/** 可疑的调试参数读取点 */
class SuspiciousDebugAccess extends RequestParamAccess {
  SuspiciousDebugAccess() {
    isDebugParamName(this.getParamName())
  }
}

/** 调试参数所在的 if 条件分支包含 return 或安全状态写入 */
class DebugBypassGuard extends IfStmt {
  SuspiciousDebugAccess access;

  DebugBypassGuard() {
    access.getParent*() = this.getCondition()
    and (
      // 分支体中直接 return
      exists(ReturnStmt r | r.getParent*() = this.getThen())
      or
      // 分支体中设置布尔标志（isAdmin = true / authenticated = true）
      exists(AssignExpr ae |
        ae.getParent*() = this.getThen()
        and ae.getDest().(VarAccess).getVariable().getName()
               .toLowerCase()
               .regexpMatch(".*(admin|auth|permit|role|bypass|skip).*")
      )
    )
  }

  SuspiciousDebugAccess getAccess() { result = access }
}

from DebugBypassGuard guard
select
  guard.getLocation().getFile().getRelativePath()    as file,
  guard.getLocation().getStartLine()                 as line,
  guard.getAccess().getParamName()                   as param_name,
  "疑似调试参数绕过认证分支"                          as message
