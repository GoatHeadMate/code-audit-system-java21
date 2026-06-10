/**
 * 查找项目中所有 H2 DataSource / EmbeddedDatabase 配置点。
 * 用于辅助判断 H2 数据库的使用范围和配置方式。
 */
import java

from ClassInstanceExpr cie
where
  cie.getConstructedType().getName().matches("%EmbeddedDatabaseBuilder%")
  or cie.getConstructedType().getQualifiedName().matches("%.H2%DataSource%")
  or (
    cie.getConstructedType().getName().matches("%DataSource%")
    and exists(StringLiteral s |
      s.getParent+() = cie
      and s.getLiteral().toLowerCase().matches("%jdbc:h2%")
    )
  )
select
  cie.getLocation().getFile().getRelativePath() as file,
  cie.getLocation().getStartLine()              as line,
  cie.getConstructedType().getName()            as type_name,
  "H2 数据源配置点"                              as message
