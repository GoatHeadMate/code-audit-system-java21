package com.huawei.audit.analysis.impl;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.agent.ClaudeGateway;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

class LlmSinkExpanderTest {

    @Test
    void expandsSnakeCaseDependenciesAndNormalizesThePrompt() {
        RecordingGateway gateway = new RecordingGateway("""
                [
                  {
                    "methodName": "executeUnsafe",
                    "receiverType": "com.example.Executor",
                    "category": "COMMAND_EXECUTION"
                  }
                ]
                """);

        var rules = new LlmSinkExpander().expand(
                List.of(
                        dependency(" com.example ", " dangerous-lib ", "1.0"),
                        dependency("com.example", "dangerous-lib", "1.0"),
                        dependency("", "missing-group", "1.0"),
                        dependency("missing-artifact", "", "1.0")
                ),
                gateway,
                Path.of(".")
        );

        assertThat(gateway.prompts).singleElement()
                .satisfies(prompt -> {
                    assertThat(prompt).contains("com.example:dangerous-lib:1.0");
                    assertThat(count(prompt, "com.example:dangerous-lib:1.0"))
                            .isEqualTo(1);
                    assertThat(prompt).doesNotContain("missing-group");
                    assertThat(prompt).doesNotContain("missing-artifact");
                });
        assertThat(rules).singleElement()
                .satisfies(rule -> {
                    assertThat(rule.methodNamePattern())
                            .isEqualTo("executeUnsafe");
                    assertThat(rule.receiverTypePattern())
                            .isEqualTo("com.example.executor");
                    assertThat(rule.category())
                            .isEqualTo("COMMAND_EXECUTION");
                });
    }

    @Test
    void acceptsLegacyCamelCaseDependencyKeys() {
        RecordingGateway gateway = new RecordingGateway("[]");

        new LlmSinkExpander().expand(
                List.of(Map.of(
                        "groupId", "legacy.group",
                        "artifactId", "legacy-artifact"
                )),
                gateway,
                Path.of(".")
        );

        assertThat(gateway.prompts).singleElement()
                .asString()
                .contains("legacy.group:legacy-artifact");
    }

    @Test
    void skipsClaudeWhenNoCompleteCoordinatesRemain() {
        RecordingGateway gateway = new RecordingGateway("[]");

        var rules = new LlmSinkExpander().expand(
                List.of(
                        dependency("", "artifact", ""),
                        dependency("group", "", "")
                ),
                gateway,
                Path.of(".")
        );

        assertThat(rules).isEmpty();
        assertThat(gateway.prompts).isEmpty();
    }

    @Test
    void degradesToNoRulesWhenClaudeFails() {
        ClaudeGateway gateway = new FailingGateway();

        var rules = new LlmSinkExpander().expand(
                List.of(dependency("com.example", "dangerous-lib", "1.0")),
                gateway,
                Path.of(".")
        );

        assertThat(rules).isEmpty();
    }

    private static Map<String, String> dependency(
            String groupId,
            String artifactId,
            String version
    ) {
        return Map.of(
                "group_id", groupId,
                "artifact_id", artifactId,
                "version", version
        );
    }

    private static int count(String value, String needle) {
        int matches = 0;
        int offset = 0;
        while ((offset = value.indexOf(needle, offset)) >= 0) {
            matches++;
            offset += needle.length();
        }
        return matches;
    }

    private static final class RecordingGateway implements ClaudeGateway {
        private final String response;
        private final List<String> prompts = new ArrayList<>();

        private RecordingGateway(String response) {
            this.response = response;
        }

        @Override
        public String query(
                Path workingDirectory,
                String prompt,
                Duration timeout
        ) {
            prompts.add(prompt);
            return response;
        }

        @Override
        public String supervise(
                Path workingDirectory,
                Path sourceRoot,
                String prompt,
                Map<String, AgentDef> agents,
                Consumer<String> eventConsumer
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean available() {
            return true;
        }
    }

    private static final class FailingGateway implements ClaudeGateway {
        @Override
        public String query(
                Path workingDirectory,
                String prompt,
                Duration timeout
        ) {
            throw new IllegalStateException("sidecar unavailable");
        }

        @Override
        public String supervise(
                Path workingDirectory,
                Path sourceRoot,
                String prompt,
                Map<String, AgentDef> agents,
                Consumer<String> eventConsumer
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean available() {
            return false;
        }
    }
}
