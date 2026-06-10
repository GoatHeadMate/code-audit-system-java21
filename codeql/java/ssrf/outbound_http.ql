/**
 * 查找所有对外发起 HTTP 请求的代码位置（枚举查询）。
 * sink 定义来自共享库 sinks/SsrfSinks.qll。
 * 覆盖 URL.openConnection / RestTemplate / Apache HttpClient / OkHttp。
 */
import java

from MethodCall ma
where
  ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName(
    "java.net", "URL"
  ) and ma.getMethod().hasName("openConnection")
  or ma.getMethod().getDeclaringType().hasQualifiedName(
    "org.springframework.web.client", "RestTemplate"
  ) and ma.getMethod().getName().regexpMatch("get.*|post.*|exchange|execute")
  or ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName(
    "org.apache.http.client", "HttpClient"
  ) and ma.getMethod().hasName("execute")
  or ma.getMethod().getDeclaringType().hasQualifiedName(
    "okhttp3", "Call"
  ) and ma.getMethod().hasName("execute")
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.getMethod().getName()                     as method_name,
  ma.getMethod().getDeclaringType().getName()  as client_type
