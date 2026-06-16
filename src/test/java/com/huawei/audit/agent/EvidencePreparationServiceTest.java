package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.agent.impl.EvidencePreparationServiceImpl;
import com.huawei.audit.analysis.impl.WhiteBoxAnalysisServiceImpl;
import com.huawei.audit.config.AuditProperties;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.job.JobLogBroker;
import com.huawei.audit.source.AsyncEntryPointDiscoverer;
import com.huawei.audit.source.HttpEndpointScanner;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EvidencePreparationServiceTest {
    private static final AuditProperties TEST_PROPERTIES = new AuditProperties(
            Path.of("workspace"),
            "http://127.0.0.1:8011",
            "",
            Duration.ofMinutes(30),
            2,
            15,
            Duration.ofMinutes(30)
    );
    private static final OrchestratorProperties TEST_ORCH_PROPERTIES =
            new OrchestratorProperties(true, 10, 5, 80);

    @TempDir
    Path tempDir;

    @Test
    void writesBoundedCandidateReviewPackage() throws Exception {
        Path source = tempDir.resolve("source");
        Files.createDirectories(source);
        Files.writeString(source.resolve("Controller.java"), """
                import org.springframework.web.bind.annotation.*;

                @RestController
                class Controller {
                    @PostMapping("/run")
                    void run(@RequestBody String command) throws Exception {
                        new ProcessBuilder("/bin/bash", "-c", command).start();
                    }
                }
                """);

        HttpEndpointScanner endpoints = new HttpEndpointScanner();
        EvidencePreparationService service = new EvidencePreparationServiceImpl(
                new WhiteBoxAnalysisServiceImpl(List.of(endpoints)),
                new ObjectMapper(),
                new JobLogBroker(),
                TEST_PROPERTIES,
                TEST_ORCH_PROPERTIES,
                null
        );
        AuditJob job = new AuditJob("evidence1", "java");
        job.workDir(tempDir.resolve("audit_evidence1"));
        Files.createDirectories(job.workDir());

        var result = service.prepare(
                job,
                source,
                List.of("code_execution", "authorization"),
                List.of()
        );

        Path task = Path.of(result.manifest().get("code_execution"));
        assertThat(task).isRegularFile();
        String taskJson = Files.readString(task);
        assertThat(taskJson)
                .contains("\"mode\" : \"candidate-path-whitebox\"")
                .contains("\"candidate_count\" : 1")
                .contains("\"candidate_chunks\"");
        assertThat(result.analysisSummary())
                .containsEntry("discovered_entrypoints", 1L)
                .containsEntry("bound_entrypoints", 1L)
                .containsEntry("entrypoints_reaching_sink", 1L);

        Path authorizationTask = Path.of(
                result.manifest().get("authorization")
        );
        var authorizationJson = new ObjectMapper().readTree(
                authorizationTask.toFile()
        );
        assertThat(authorizationJson.path("authorization_surface"))
                .singleElement()
                .satisfies(endpoint -> {
                    assertThat(endpoint.path("path").asText())
                            .isEqualTo("/run");
                    assertThat(endpoint.path("method_security_present").asBoolean())
                            .isFalse();
                    assertThat(endpoint.path("reachable_sink_categories"))
                            .extracting(node -> node.asText())
                            .contains("COMMAND_EXECUTION");
                });
    }

    @Test
    void writesStoredCandidatePackageForSstiHunter() throws Exception {
        Path source = tempDir.resolve("stored-source");
        Files.createDirectories(source);
        Files.writeString(source.resolve("StoredFlow.java"), """
                import org.springframework.web.bind.annotation.*;
                import org.springframework.scheduling.annotation.Scheduled;

                @RestController
                class RuleController {
                    RuleRepository repository;

                    @PostMapping("/rules")
                    void save(@RequestBody Rule rule) {
                        repository.save(rule);
                    }
                }

                class RuleJob {
                    RuleRepository repository;

                    @Scheduled(fixedDelay = 1000)
                    void execute() {
                        Rule rule = repository.findFirst();
                        MVEL.executeExpression("method=" + rule.method);
                    }
                }

                interface RuleRepository {
                    Rule save(Rule rule);
                    Rule findFirst();
                }

                class Rule {
                    String method;
                }
                """);

        ObjectMapper mapper = new ObjectMapper();
        EvidencePreparationService service = new EvidencePreparationServiceImpl(
                new WhiteBoxAnalysisServiceImpl(List.of(
                        new HttpEndpointScanner(),
                        new AsyncEntryPointDiscoverer()
                )),
                mapper,
                new JobLogBroker(),
                TEST_PROPERTIES,
                TEST_ORCH_PROPERTIES,
                null
        );
        AuditJob job = new AuditJob("stored1", "java");
        job.workDir(tempDir.resolve("audit_stored1"));
        Files.createDirectories(job.workDir());

        var result = service.prepare(job, source, List.of("code_execution"), List.of());
        var task = mapper.readTree(
                Path.of(result.manifest().get("code_execution")).toFile()
        );

        assertThat(task.path("stored_candidate_count").asInt()).isEqualTo(1);
        assertThat(task.path("stored_candidate_chunks").get(0).asText())
                .endsWith("stored-candidates-0001.json");
        assertThat(result.analysisSummary())
                .containsEntry("stored_candidates", 1L)
                .containsEntry("storage_accesses", 2L);
    }

    @Test
    void splitsLargeCandidatePackagesBeforeClaudeReadLimit() throws Exception {
        Path source = tempDir.resolve("large-source");
        Files.createDirectories(source);
        String largeArgument = "a".repeat(20_000);
        List<String> methods = new ArrayList<>();
        for (int index = 0; index < 6; index++) {
            methods.add("""
                    @PostMapping("/run-%d")
                    void run%d() throws Exception {
                        new ProcessBuilder("%s").start();
                    }
                    """.formatted(index, index, largeArgument));
        }
        Files.writeString(source.resolve("LargeController.java"), """
                import org.springframework.web.bind.annotation.*;

                @RestController
                class LargeController {
                %s
                }
                """.formatted(String.join("\n", methods)));

        ObjectMapper mapper = new ObjectMapper();
        EvidencePreparationService service = new EvidencePreparationServiceImpl(
                new WhiteBoxAnalysisServiceImpl(List.of(
                        new HttpEndpointScanner()
                )),
                mapper,
                new JobLogBroker(),
                TEST_PROPERTIES,
                TEST_ORCH_PROPERTIES,
                null
        );
        AuditJob job = new AuditJob("large1", "java");
        job.workDir(tempDir.resolve("audit_large1"));
        Files.createDirectories(job.workDir());

        var result = service.prepare(
                job,
                source,
                List.of("code_execution"),
                List.of()
        );
        var task = mapper.readTree(
                Path.of(result.manifest().get("code_execution")).toFile()
        );

        assertThat(task.path("candidate_count").asInt()).isEqualTo(6);
        assertThat(task.path("candidate_chunks").size()).isGreaterThan(1);
        for (var chunk : task.path("candidate_chunks")) {
            assertThat(Files.size(Path.of(chunk.asText())))
                    .isLessThanOrEqualTo(64 * 1_024);
        }
    }
}
