package com.huawei.audit.orchestrator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

@Component
public class TechProfileScanner {

    public Map<String, Object> scan(Path sourceRoot) {
        Map<String, Object> profile = new LinkedHashMap<>();
        Path pom = findFirst(sourceRoot, "pom.xml");
        Path gradle = findFirst(sourceRoot, "build.gradle", "build.gradle.kts");
        List<Map<String, String>> dependencies = pom == null
                ? List.of()
                : readMavenDependencies(pom);

        boolean hasJava = findFirst(sourceRoot, ".java") != null || pom != null || gradle != null;
        profile.put("primary_language", hasJava ? "java" : "unknown");
        profile.put("build_tool", pom != null ? "maven" : gradle != null ? "gradle" : "unknown");
        profile.put("web_framework", detectFramework(dependencies));
        profile.put("orm", detectOrm(dependencies));
        profile.put("security_libs", detectSecurityLibraries(dependencies));
        profile.put("dependencies", dependencies);
        profile.put("app_package", detectApplicationPackage(sourceRoot));
        return profile;
    }

    private String detectApplicationPackage(Path sourceRoot) {
        Path javaFile = findFirst(sourceRoot, ".java");
        if (javaFile == null) {
            return "";
        }
        try {
            Matcher matcher = Pattern.compile(
                    "(?m)^\\s*package\\s+([A-Za-z_][\\w.]*)\\s*;"
            ).matcher(Files.readString(javaFile));
            return matcher.find() ? matcher.group(1) : "";
        } catch (IOException ignored) {
            return "";
        }
    }

    private Path findFirst(Path root, String... namesOrSuffixes) {
        try (var paths = Files.walk(root, 8)) {
            return paths.filter(Files::isRegularFile)
                    .filter(path -> {
                        String fileName = path.getFileName().toString();
                        for (String name : namesOrSuffixes) {
                            if (name.startsWith(".") && fileName.endsWith(name)) {
                                return true;
                            }
                            if (fileName.equals(name)) {
                                return true;
                            }
                        }
                        return false;
                    })
                    .findFirst()
                    .orElse(null);
        } catch (IOException ignored) {
            return null;
        }
    }

    private List<Map<String, String>> readMavenDependencies(Path pom) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");

            NodeList nodes = factory.newDocumentBuilder()
                    .parse(pom.toFile())
                    .getElementsByTagName("dependency");
            List<Map<String, String>> dependencies = new ArrayList<>();
            for (int index = 0; index < nodes.getLength() && dependencies.size() < 100; index++) {
                Element element = (Element) nodes.item(index);
                dependencies.add(Map.of(
                        "group_id", childText(element, "groupId"),
                        "artifact_id", childText(element, "artifactId"),
                        "version", childText(element, "version")
                ));
            }
            return dependencies;
        } catch (Exception ignored) {
            return List.of();
        }
    }

    private String childText(Element parent, String tag) {
        NodeList nodes = parent.getElementsByTagName(tag);
        return nodes.getLength() == 0 ? "" : nodes.item(0).getTextContent().strip();
    }

    private String detectFramework(List<Map<String, String>> dependencies) {
        return contains(dependencies, "spring-boot") ? "Spring Boot"
                : contains(dependencies, "spring-web") ? "Spring"
                : contains(dependencies, "jersey") ? "JAX-RS"
                : "unknown";
    }

    private String detectOrm(List<Map<String, String>> dependencies) {
        return contains(dependencies, "mybatis") ? "MyBatis"
                : contains(dependencies, "hibernate") ? "Hibernate"
                : contains(dependencies, "spring-data-jpa") ? "JPA"
                : "unknown";
    }

    private List<String> detectSecurityLibraries(List<Map<String, String>> dependencies) {
        List<String> libraries = new ArrayList<>();
        if (contains(dependencies, "spring-security")) {
            libraries.add("Spring Security");
        }
        if (contains(dependencies, "shiro")) {
            libraries.add("Apache Shiro");
        }
        return libraries;
    }

    private boolean contains(List<Map<String, String>> dependencies, String token) {
        String lower = token.toLowerCase(Locale.ROOT);
        return dependencies.stream()
                .flatMap(dependency -> dependency.values().stream())
                .map(value -> value.toLowerCase(Locale.ROOT))
                .anyMatch(value -> value.contains(lower));
    }
}
