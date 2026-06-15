package com.huawei.audit.analysis.impl;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigTemplateScannerTest {

    @TempDir
    Path tempDir;

    @Test
    void scanFindsCommandTemplateInYaml() throws IOException {
        Files.writeString(tempDir.resolve("application.yml"), """
                app:
                  command: "bash -c ${param}"
                  name: "test"
                """);

        var scanner = new ConfigTemplateScanner();
        var templates = scanner.scan(tempDir);

        assertThat(templates).singleElement().satisfies(template -> {
            assertThat(template.configFile()).isEqualTo("application.yml");
            assertThat(template.key()).isEqualTo("app.command");
            assertThat(template.templateValue()).isEqualTo("bash -c ${param}");
            assertThat(template.placeholders()).containsExactly("param");
        });
    }

    @Test
    void scanFindsCommandTemplateInProperties() throws IOException {
        Files.writeString(tempDir.resolve("config.properties"), """
                exec.cmd=sh -c ${userInput}
                app.name=MyApp
                """);

        var scanner = new ConfigTemplateScanner();
        var templates = scanner.scan(tempDir);

        assertThat(templates).singleElement().satisfies(template -> {
            assertThat(template.configFile()).isEqualTo("config.properties");
            assertThat(template.key()).isEqualTo("exec.cmd");
            assertThat(template.templateValue()).isEqualTo("sh -c ${userInput}");
            assertThat(template.placeholders()).containsExactly("userInput");
        });
    }

    @Test
    void scanFindsCommandTemplateInXml() throws IOException {
        Files.writeString(tempDir.resolve("config.xml"), """
                <configuration>
                    <command>bash -c ${arg}</command>
                    <name>test</name>
                </configuration>
                """);

        var scanner = new ConfigTemplateScanner();
        var templates = scanner.scan(tempDir);

        assertThat(templates).singleElement().satisfies(template -> {
            assertThat(template.configFile()).isEqualTo("config.xml");
            assertThat(template.key()).isEqualTo("command");
            assertThat(template.templateValue()).isEqualTo("bash -c ${arg}");
            assertThat(template.placeholders()).containsExactly("arg");
        });
    }

    @Test
    void scanIgnoresNonCommandTemplates() throws IOException {
        Files.writeString(tempDir.resolve("app.yml"), """
                app:
                  greeting: "Hello ${name}"
                  url: "https://${host}/api"
                """);

        var scanner = new ConfigTemplateScanner();
        var templates = scanner.scan(tempDir);

        assertThat(templates).isEmpty();
    }

    @Test
    void findSinksGeneratesCommandExecutionSink() throws IOException {
        Files.writeString(tempDir.resolve("application.yml"), """
                app:
                  command: "bash -c ${param}"
                """);

        var scanner = new ConfigTemplateScanner();
        var index = createIndexWithMethod(
                "TaskService#execute/1",
                "TaskService",
                "execute",
                1,
                List.of(
                        call("replace", "template", "String", 2),
                        call("exec", "Runtime.getRuntime()", "Runtime", 1)
                ),
                "@Value String TaskService.execute"
        );

        var sinks = scanner.findSinks(tempDir, index);

        assertThat(sinks).singleElement().satisfies(sink -> {
            assertThat(sink.category()).isEqualTo("COMMAND_EXECUTION");
            assertThat(sink.api()).contains("ConfigTemplate:");
            assertThat(sink.api()).contains("→replace→exec");
        });
    }

    @Test
    void findSinksSkipsMethodsNoConfigRead() throws IOException {
        Files.writeString(tempDir.resolve("application.yml"), """
                app:
                  command: "bash -c ${param}"
                """);

        var scanner = new ConfigTemplateScanner();
        var index = createIndexWithMethod(
                "TaskService#execute/1",
                "TaskService",
                "execute",
                1,
                List.of(call("replace", "template", "String", 2)),
                null
        );

        var sinks = scanner.findSinks(tempDir, index);

        assertThat(sinks).isEmpty();
    }

    @Test
    void scanHandlesMultiplePlaceholders() throws IOException {
        Files.writeString(tempDir.resolve("app.yml"), """
                app:
                  cmd: "/bin/${shell} -c ${command}"
                """);

        var scanner = new ConfigTemplateScanner();
        var templates = scanner.scan(tempDir);

        assertThat(templates).singleElement().satisfies(template -> {
            assertThat(template.placeholders()).containsExactly("shell", "command");
        });
    }

    private SourceIndex createIndexWithMethod(
            String id,
            String className,
            String methodName,
            int parameterCount,
            List<CallSite> calls,
            String signature
    ) {
        MethodNode method = new MethodNode(
                id,
                className,
                methodName,
                parameterCount,
                List.of(),
                className + ".java",
                1,
                10,
                signature != null ? signature : methodName,
                calls,
                Map.of(),
                List.of(),
                List.of()
        );
        return SourceIndex.create(
                List.of(method),
                List.of(),
                Map.of(),
                List.of()
        );
    }

    private CallSite call(
            String methodName,
            String receiver,
            String receiverType,
            int argumentCount
    ) {
        return new CallSite(
                methodName,
                receiver,
                receiverType,
                argumentCount,
                List.of("String"),
                List.of("arg"),
                1,
                receiver + "." + methodName + "(arg)"
        );
    }
}
