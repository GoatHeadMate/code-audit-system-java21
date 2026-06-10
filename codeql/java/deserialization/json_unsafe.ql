/**
 * 查找 JSON 库的不安全配置。
 * 覆盖 Jackson ObjectMapper.enableDefaultTyping() /
 * Fastjson parseObject(str, Object.class) 自动类型推断 /
 * SerializeConfig.globalInstance 全局宽松设置。
 */
import java

from MethodCall ma
where
  (
    ma.getMethod().hasName("enableDefaultTyping")
    or
    ma.getMethod().getDeclaringType().hasQualifiedName(
      "com.alibaba.fastjson", "JSON"
    )
    and ma.getMethod().hasName("parseObject")
    or
    ma.getMethod().getDeclaringType().hasQualifiedName(
      "com.alibaba.fastjson.serializer", "SerializeConfig"
    )
    and ma.getMethod().hasName("getGlobalInstance")
  )
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.toString()                                as expression
