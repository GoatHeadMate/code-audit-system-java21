package com.huawei.audit.api;

import com.huawei.audit.api.ApiDtos.FindingsResponse;
import com.huawei.audit.api.ApiDtos.JobListResponse;
import com.huawei.audit.api.ApiDtos.JobStatusResponse;
import com.huawei.audit.api.ApiDtos.SubmitResponse;
import com.huawei.audit.config.RuntimeExecutables;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.domain.JobStatus;
import com.huawei.audit.job.AuditJobStore;
import com.huawei.audit.job.JobLogBroker;
import com.huawei.audit.orchestrator.AuditOrchestrator;
import com.huawei.audit.source.SourceWorkspaceService;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@RestController
public class AuditController {
    private final AuditJobStore jobs;
    private final JobLogBroker logs;
    private final SourceWorkspaceService sources;
    private final AuditOrchestrator orchestrator;
    private final RuntimeExecutables executables;
    private final OrchestratorProperties orchestratorProperties;

    public AuditController(
            AuditJobStore jobs,
            JobLogBroker logs,
            SourceWorkspaceService sources,
            AuditOrchestrator orchestrator,
            RuntimeExecutables executables,
            OrchestratorProperties orchestratorProperties
    ) {
        this.jobs = jobs;
        this.logs = logs;
        this.sources = sources;
        this.orchestrator = orchestrator;
        this.executables = executables;
        this.orchestratorProperties = orchestratorProperties;
    }

    @PostMapping(
            path = "/audit",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE
    )
    public ResponseEntity<SubmitResponse> submit(
            @RequestParam(required = false) MultipartFile file,
            @RequestParam(name = "git_url", required = false) String gitUrl,
            @RequestParam(defaultValue = "java") String lang
    ) throws IOException {
        boolean hasFile = file != null && !file.isEmpty();
        boolean hasGit = gitUrl != null && !gitUrl.isBlank();
        if (hasFile == hasGit) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "file and git_url must contain exactly one source"
            );
        }
        if (!"java".equals(lang)) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "only java is currently supported"
            );
        }

        AuditJob job = jobs.create(lang);
        if (hasGit) {
            job.sourceType("git");
            job.gitUrl(gitUrl.strip());
        } else {
            job.sourceType("zip");
            Path zipPath = sources.uploadDirectory().resolve(job.jobId() + ".zip");
            Files.copy(file.getInputStream(), zipPath, StandardCopyOption.REPLACE_EXISTING);
            job.zipPath(zipPath);
        }

        orchestrator.submit(job);
        return ResponseEntity.accepted().body(new SubmitResponse(
                job.jobId(),
                JobStatus.PENDING.value(),
                "audit submitted; use /audit/" + job.jobId() + "/logs for progress"
        ));
    }

    @GetMapping("/audit")
    public JobListResponse list() {
        return new JobListResponse(
                jobs.list().stream().map(JobStatusResponse::from).toList()
        );
    }

    @GetMapping("/audit/{jobId}")
    public JobStatusResponse status(@PathVariable String jobId) {
        return JobStatusResponse.from(requireJob(jobId));
    }

    @GetMapping("/audit/{jobId}/findings")
    public ResponseEntity<FindingsResponse> findings(@PathVariable String jobId) {
        AuditJob job = requireJob(jobId);
        if (job.status() != JobStatus.DONE && job.status() != JobStatus.FAILED) {
            return ResponseEntity.status(HttpStatus.ACCEPTED).build();
        }
        return ResponseEntity.ok(FindingsResponse.from(job));
    }

    @GetMapping(
            path = "/audit/{jobId}/logs",
            produces = MediaType.TEXT_EVENT_STREAM_VALUE
    )
    public SseEmitter logs(@PathVariable String jobId) {
        return logs.subscribe(requireJob(jobId));
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of(
                "status", "ok",
                "jobs", jobs.list().size(),
                "codeql_available", executables.codeqlAvailable(),
                "claude_available", executables.claudeAvailable(),
                "intelligent_orchestrator", orchestratorProperties.enabled(),
                "agent_framework", "langchain4j+langgraph4j",
                "agent_topology", "one-supervisor+native-subagents",
                "claude_processes_per_job", 1
        );
    }

    private AuditJob requireJob(String jobId) {
        return jobs.find(jobId).orElseThrow(() -> new ResponseStatusException(
                HttpStatus.NOT_FOUND,
                "job not found: " + jobId
        ));
    }
}
