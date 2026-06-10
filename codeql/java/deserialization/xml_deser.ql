/**
 * 查找 XML 反序列化入口。
 * 覆盖 XStream.fromXML() / JAXB Unmarshaller.unmarshal() /
 * XMLDecoder.readObject() 等常用 XML 反序列化调用。
 */
import java

from MethodCall ma
where
  (
    ma.getMethod().getDeclaringType().hasQualifiedName(
      "com.thoughtworks.xstream", "XStream"
    )
    and ma.getMethod().hasName("fromXML")
    or
    ma.getMethod().getDeclaringType().hasQualifiedName(
      "javax.xml.bind", "Unmarshaller"
    )
    and ma.getMethod().hasName("unmarshal")
    or
    ma.getMethod().getDeclaringType().hasQualifiedName(
      "java.beans", "XMLDecoder"
    )
    and ma.getMethod().hasName("readObject")
  )
select
  ma.getLocation().getFile().getRelativePath() as file,
  ma.getLocation().getStartLine()              as line,
  ma.getMethod().getName()                     as method_name
