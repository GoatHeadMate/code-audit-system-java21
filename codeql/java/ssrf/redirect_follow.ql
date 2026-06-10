/**
 * 查找 HTTP 重定向自动跟随配置。
 * setFollowRedirects(true) 允许 HTTP 客户端自动跟随 3xx 重定向，
 * 攻击者可利用此机制绕过 SSRF URL 白名单。
 */
import java

from MethodCall ma
where
  ma.getMethod().hasName("setFollowRedirects")
  or ma.getMethod().getDeclaringType().hasQualifiedName(
    "org.apache.http.impl.client", "HttpClientBuilder"
  )
  and ma.getMethod().hasName("disableRedirectHandling")
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.toString()                                as setting_value
