/**
 * Java 反序列化 Sink 库（共享）。
 *
 * 涵盖：原生 ObjectInputStream、XMLDecoder、
 * Jackson ObjectMapper、Gson、Kryo、SnakeYAML。
 */
import java
import semmle.code.java.dataflow.DataFlow

/** new ObjectInputStream(inputStream) — 原生 Java 反序列化入口 */
class ObjectInputStreamSink extends DataFlow::Node {
  ObjectInputStreamSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().getASupertype*()
          .hasQualifiedName("java.io", "ObjectInputStream")
      and this.asExpr() = cie.getArgument(0)
    )
  }
}

/** new XMLDecoder(inputStream) — XML Bean 反序列化 */
class XmlDecoderSink extends DataFlow::Node {
  XmlDecoderSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.beans", "XMLDecoder")
      and this.asExpr() = cie.getArgument(0)
    )
  }
}

/** ObjectMapper.readValue(src, type) — Jackson JSON 反序列化 */
class JacksonReadValueSink extends DataFlow::Node {
  JacksonReadValueSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper")
      and ma.getMethod().hasName("readValue")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** Gson.fromJson(json, type) */
class GsonSink extends DataFlow::Node {
  GsonSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("com.google.gson", "Gson")
      and ma.getMethod().hasName("fromJson")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** Kryo.readObject / readClassAndObject */
class KryoSink extends DataFlow::Node {
  KryoSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType().getName().regexpMatch("(?i).*[Kk]ryo.*")
      and ma.getMethod().getName().matches("read%")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** SnakeYAML Yaml.load(input) — 不安全的 YAML 反序列化 */
class SnakeYamlSink extends DataFlow::Node {
  SnakeYamlSink() {
    exists(MethodCall ma |
      ma.getMethod().getDeclaringType()
          .hasQualifiedName("org.yaml.snakeyaml", "Yaml")
      and ma.getMethod().hasName("load")
      and this.asExpr() = ma.getArgument(0)
    )
  }
}

/** 统一反序列化 sink */
class AnyDeserSink extends DataFlow::Node {
  AnyDeserSink() {
    this instanceof ObjectInputStreamSink or
    this instanceof XmlDecoderSink or
    this instanceof JacksonReadValueSink or
    this instanceof GsonSink or
    this instanceof KryoSink or
    this instanceof SnakeYamlSink
  }
}
