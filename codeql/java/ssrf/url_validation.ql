/**
 * 查找 URL 白名单校验或内网 IP 过滤逻辑。
 * 匹配 IP 地址正则（10.x / 172.16-31.x / 192.168.x / 127.x / 0.0.0.0）
 * 以及域名白名单比较代码。
 */
import java

from MethodCall ma
where
  exists(StringLiteral lit |
    lit = ma.getAnArgument()
    and (
      lit.getValue().regexpMatch(".*(10\\.|127\\.|0\\.0\\.0\\.0|192\\.168|172\\.(1[6-9]|2[0-9]|3[0-1])).*")
      or lit.getValue().regexpMatch("(?i).*(localhost|internal|private|intranet|metadata).*")
    )
  )
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  "内网IP/域名过滤"                            as validation_type,
  ma.toString()                                as expression
