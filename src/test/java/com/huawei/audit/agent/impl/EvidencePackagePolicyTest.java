package com.huawei.audit.agent.impl;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CandidatePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.EntryPoint;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodStep;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class EvidencePackagePolicyTest {
    @Test
    void mapsEveryConfiguredHunterToAtLeastOneSinkCategory() {
        Map<String, String> expected = Map.of(
                "sql_injection", "SQL_EXECUTION",
                "http_output", "HTTP_RESPONSE_WRITE",
                "unsafe_parsing", "XML_PARSE",
                "component_vulns", "ACTUATOR_ENDPOINT",
                "code_execution", "COMMAND_EXECUTION",
                "file_operations", "FILE_WRITE"
        );

        expected.forEach((hunter, category) ->
                assertThat(EvidencePackagePolicy.sinkCategories(hunter))
                        .as(hunter)
                        .contains(category));
    }

    @Test
    void summarizesAuthorizationSurfaceWithReachableSinks() {
        EntryPoint entryPoint = new EntryPoint(
                "entry-1",
                "HTTP",
                List.of("POST"),
                "/admin/run",
                "AdminController",
                "run",
                "AdminController.java",
                10,
                "spring-mvc",
                List.of(),
                "annotation",
                "HIGH",
                "AdminController#run/1",
                "BOUND"
        );
        Sink sink = new Sink(
                "sink-1",
                "COMMAND_EXECUTION",
                "new ProcessBuilder",
                "CommandService#run/1",
                "CommandService.java",
                20,
                "new ProcessBuilder(command)"
        );
        CandidatePath candidate = new CandidatePath(
                "candidate-1",
                entryPoint,
                sink,
                List.of(new MethodStep(
                        "AdminController#run/1",
                        "AdminController",
                        "run",
                        1,
                        "AdminController.java",
                        10,
                        12,
                        "void run(String command)"
                )),
                List.of(),
                "HIGH",
                1,
                "PENDING_CLAUDE_REVIEW",
                "LIKELY",
                List.of(),
                "REQUEST_CONTROLLED"
        );

        assertThat(EvidencePackagePolicy.authorizationSurface(
                List.of(entryPoint),
                List.of(candidate)
        )).singleElement().satisfies(summary -> {
            assertThat(summary)
                    .containsEntry("path", "/admin/run")
                    .containsEntry("method_security_present", false)
                    .containsEntry("candidate_path_count", 1);
            assertThat(summary.get("reachable_sink_categories"))
                    .isEqualTo(List.of("COMMAND_EXECUTION"));
        });
    }

    @Test
    void buildsEndpointReviewSurfaceForKeywordMatchedHunterCategories() {
        EntryPoint xss = entryPoint("xss-1", "/xss/reflect",
                "XssController", "reflect");
        EntryPoint xxe = entryPoint("xxe-1", "/xxe/dom4j",
                "XxeController", "dom4j");
        EntryPoint index = entryPoint("index-1", "/index",
                "IndexController", "index");

        assertThat(EvidencePackagePolicy.endpointReviewSurface(
                "http_output",
                List.of(xss, xxe, index),
                List.of()
        )).singleElement().satisfies(surface -> {
            assertThat(surface)
                    .containsEntry("path", "/xss/reflect")
                    .containsEntry("discovery_source", "keyword-surface");
        });

        assertThat(EvidencePackagePolicy.endpointReviewSurface(
                "unsafe_parsing",
                List.of(xss, xxe, index),
                List.of()
        )).singleElement().satisfies(surface ->
                assertThat(surface).containsEntry("path", "/xxe/dom4j"));
    }

    private EntryPoint entryPoint(
            String id,
            String path,
            String className,
            String methodName
    ) {
        return new EntryPoint(
                id,
                "HTTP",
                List.of("GET"),
                path,
                className,
                methodName,
                className + ".java",
                10,
                "spring-mvc",
                List.of(),
                "annotation",
                "HIGH",
                className + "#" + methodName + "/0",
                "BOUND"
        );
    }
}
