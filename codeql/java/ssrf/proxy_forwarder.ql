/**
 * 检测自定义 HTTP 请求转发/代理模式。
 * 查找类名含 Client/Rest/Http/Backend 的类上被调用的转发类方法。
 * 覆盖非标准 HTTP 客户端封装（如 BackendRestClient、InternalHttpProxy 等），
 * 这些自定义客户端不在标准 SSRF sink 列表中但可构成 SSRF 转发链。
 */
import java

from MethodCall ma
where
  ma.getMethod().getDeclaringType().getName().regexpMatch(
    "(?i).*(Client|Rest|Http|Proxy|Forward|Request|Backend|Dispatch).*"
  )
  and ma.getMethod().getName().regexpMatch(
    "(?i).*(invoke|request|send|forward|dispatch|distribute|execute|call|fetch).*"
  )
  and not ma.getMethod().getDeclaringType().getName().regexpMatch(
    "(?i).*(Test|Mock|Stub|Abstract).*"
  )
select
  ma.getLocation().getFile().getRelativePath()                     as file,
  ma.getLocation().getStartLine()                                  as line,
  ma.getMethod().getDeclaringType().getName()                      as client_class,
  ma.getMethod().getName()                                         as method_name,
  ma.getEnclosingCallable().getName()                              as caller_method,
  ma.getEnclosingCallable().getDeclaringType().getName()           as caller_class
