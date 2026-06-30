package com.huawei.audit.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.huawei.audit.agent.ClaudeGateway;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.job.AuditJobStore;
import com.huawei.audit.job.JobLogBroker;
import com.huawei.audit.memory.AuditMemoryService;
import com.huawei.audit.orchestrator.AuditOrchestrator;
import com.huawei.audit.source.InterfaceInventoryService;
import com.huawei.audit.source.SourceWorkspaceService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.server.ResponseStatusException;

class AuditControllerTest {
    @TempDir
    Path tempDir;

    @Test
    void previewsInterfacesAndStartsOnlyTheSelectedIds() throws Exception {
        AuditJobStore jobs = mock(AuditJobStore.class);
        SourceWorkspaceService sources = mock(SourceWorkspaceService.class);
        InterfaceInventoryService inventory = mock(
                InterfaceInventoryService.class
        );
        AuditOrchestrator orchestrator = mock(AuditOrchestrator.class);
        AuditJob job = new AuditJob("preview1", "java");
        Path sourceRoot = Files.createDirectories(tempDir.resolve("source"));
        var endpoint = endpoint("endpoint-1", "/api/run");

        when(jobs.create("java")).thenReturn(job);
        when(jobs.find(job.jobId())).thenReturn(Optional.of(job));
        when(sources.uploadDirectory()).thenReturn(tempDir);
        when(sources.prepare(job)).thenAnswer(invocation -> {
            job.projectPath(sourceRoot);
            return new SourceWorkspaceService.PreparedSource(
                    sourceRoot,
                    "cache"
            );
        });
        when(inventory.scan(sourceRoot)).thenReturn(List.of(endpoint));

        AuditController controller = controller(
                jobs,
                sources,
                inventory,
                orchestrator
        );
        var preview = controller.previewInterfaces(
                new MockMultipartFile(
                        "file",
                        "source.zip",
                        "application/zip",
                        "zip".getBytes()
                ),
                null,
                "java"
        );

        assertThat(preview.jobId()).isEqualTo(job.jobId());
        assertThat(preview.interfaces())
                .singleElement()
                .satisfies(option -> {
                    assertThat(option.id()).isEqualTo(endpoint.id());
                    assertThat(option.route()).isEqualTo("/api/run");
                });

        var response = controller.startSelected(
                job.jobId(),
                new ApiDtos.StartAuditRequest(List.of(endpoint.id()))
        );

        assertThat(response.getStatusCode().value()).isEqualTo(202);
        assertThat(job.selectedInterfaceIds()).containsExactly(endpoint.id());
        verify(orchestrator).submit(job);
    }

    @Test
    void rejectsUnknownSelectedInterfaceIds() throws Exception {
        AuditJobStore jobs = mock(AuditJobStore.class);
        SourceWorkspaceService sources = mock(SourceWorkspaceService.class);
        InterfaceInventoryService inventory = mock(
                InterfaceInventoryService.class
        );
        AuditOrchestrator orchestrator = mock(AuditOrchestrator.class);
        AuditJob job = new AuditJob("preview2", "java");
        Path sourceRoot = Files.createDirectories(tempDir.resolve("source"));
        job.projectPath(sourceRoot);

        when(jobs.find(job.jobId())).thenReturn(Optional.of(job));
        when(inventory.scan(sourceRoot)).thenReturn(
                List.of(endpoint("known", "/known"))
        );

        AuditController controller = controller(
                jobs,
                sources,
                inventory,
                orchestrator
        );

        assertThatThrownBy(() -> controller.startSelected(
                job.jobId(),
                new ApiDtos.StartAuditRequest(List.of("unknown"))
        )).isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("unknown ids");
        assertThat(job.submitted()).isFalse();
    }

    @Test
    void recordsFindingFeedbackAsAuditMemory() {
        AuditJobStore jobs = mock(AuditJobStore.class);
        SourceWorkspaceService sources = mock(SourceWorkspaceService.class);
        InterfaceInventoryService inventory = mock(
                InterfaceInventoryService.class
        );
        AuditOrchestrator orchestrator = mock(AuditOrchestrator.class);
        AuditMemoryService memory = mock(AuditMemoryService.class);
        AuditJob job = new AuditJob("feedback1", "java");
        job.findings(List.of(Map.of(
                "rule_id", "ssrf-1",
                "vuln_type", "SSRF",
                "file_path", "Proxy.java",
                "start_line", 12
        )));
        job.setStatus(com.huawei.audit.domain.JobStatus.DONE);

        when(jobs.find(job.jobId())).thenReturn(Optional.of(job));

        AuditController controller = controller(
                jobs,
                sources,
                inventory,
                orchestrator,
                memory
        );

        var response = controller.findingFeedback(
                job.jobId(),
                0,
                new ApiDtos.FindingFeedbackRequest(
                        "false_positive",
                        "URL is restricted by a strict allowlist",
                        "reviewer"
                )
        );

        assertThat(response.verdict()).isEqualTo("FALSE_POSITIVE");
        verify(memory).rememberFeedback(
                job,
                0,
                job.findings().getFirst(),
                "FALSE_POSITIVE",
                "URL is restricted by a strict allowlist",
                "reviewer"
        );
    }

    private AuditController controller(
            AuditJobStore jobs,
            SourceWorkspaceService sources,
            InterfaceInventoryService inventory,
            AuditOrchestrator orchestrator
    ) {
        return controller(
                jobs,
                sources,
                inventory,
                orchestrator,
                mock(AuditMemoryService.class)
        );
    }

    private AuditController controller(
            AuditJobStore jobs,
            SourceWorkspaceService sources,
            InterfaceInventoryService inventory,
            AuditOrchestrator orchestrator,
            AuditMemoryService memory
    ) {
        return new AuditController(
                jobs,
                mock(JobLogBroker.class),
                sources,
                inventory,
                orchestrator,
                mock(ClaudeGateway.class),
                new OrchestratorProperties(true, 10, 5, 80),
                memory
        );
    }

    private InterfaceInventoryService.InterfaceSummary endpoint(
            String id,
            String route
    ) {
        return new InterfaceInventoryService.InterfaceSummary(
                id,
                "HTTP",
                List.of("POST"),
                route,
                "Controller",
                "run",
                "Controller.java",
                10,
                "spring-mvc",
                List.of()
        );
    }
}
