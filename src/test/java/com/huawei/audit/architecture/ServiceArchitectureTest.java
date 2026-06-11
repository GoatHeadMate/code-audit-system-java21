package com.huawei.audit.architecture;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class ServiceArchitectureTest {
    private static final Path MAIN_JAVA = Path.of("src", "main", "java");

    @Test
    void serviceContractsAreInterfaces() throws Exception {
        for (Path service : javaFiles().stream()
                .filter(path -> path.getFileName().toString()
                        .endsWith("Service.java"))
                .toList()) {
            assertThat(Files.readString(service))
                    .as("%s should declare a service interface", service)
                    .contains("public interface ");
        }
    }

    @Test
    void serviceImplementationsStayWithinThreeHundredLines() throws Exception {
        for (Path implementation : javaFiles().stream()
                .filter(path -> path.getFileName().toString()
                        .endsWith("ServiceImpl.java"))
                .toList()) {
            assertThat(Files.readAllLines(implementation).size())
                    .as("%s should stay within 300 lines", implementation)
                    .isLessThanOrEqualTo(300);
        }
    }

    private List<Path> javaFiles() throws Exception {
        try (var files = Files.walk(MAIN_JAVA)) {
            return files
                    .filter(Files::isRegularFile)
                    .filter(path ->
                            path.getFileName().toString().endsWith(".java"))
                    .toList();
        }
    }
}
