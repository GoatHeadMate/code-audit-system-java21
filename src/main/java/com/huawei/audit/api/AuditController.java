package com.huawei.audit.api;

import com.huawei.audit.api.ApiDtos.FindingsResponse;
import com.huawei.audit.api.ApiDtos.FindingFeedbackRequest;
import com.huawei.audit.api.ApiDtos.FindingFeedbackResponse;
import com.huawei.audit.api.ApiDtos.RuleCandidatesResponse;
import com.huawei.audit.api.ApiDtos.RuleDecisionRequest;
import com.huawei.audit.api.ApiDtos.RuleDecisionResponse;
import com.huawei.audit.api.ApiDtos.InterfaceOption;
import com.huawei.audit.api.ApiDtos.InterfacePreviewResponse;
import com.huawei.audit.api.ApiDtos.JobListResponse;
import com.huawei.audit.api.ApiDtos.JobStatusResponse;
import com.huawei.audit.api.ApiDtos.StartAuditRequest;
import com.huawei.audit.api.ApiDtos.SubmitResponse;
import com.huawei.audit.agent.ClaudeGateway;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.domain.JobStatus;
import com.huawei.audit.job.AuditJobStore;
import com.huawei.audit.job.JobLogBroker;
import com.huawei.audit.memory.AuditMemoryService;
import com.huawei.audit.orchestrator.AuditOrchestrator;
import com.huawei.audit.source.SourceWorkspaceService;
import com.huawei.audit.source.InterfaceInventoryService;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@RestController
public class AuditController {
    private final AuditJobStore jobs;
    private final JobLogBroker logs;
    private final SourceWorkspaceService sources;
    private final InterfaceInventoryService interfaceInventory;
    private final AuditOrchestrator orchestrator;
    private final ClaudeGateway claudeGateway;
    private final OrchestratorProperties orchestratorProperties;
    private final AuditMemoryService auditMemory;

    public AuditController(
            AuditJobStore jobs,
            JobLogBroker logs,
            SourceWorkspaceService sources,
            InterfaceInventoryService interfaceInventory,
            AuditOrchestrator orchestrator,
            ClaudeGateway claudeGateway,
            OrchestratorProperties orchestratorProperties,
            AuditMemoryService auditMemory
    ) {
        this.jobs = jobs;
        this.logs = logs;
        this.sources = sources;
        this.interfaceInventory = interfaceInventory;
        this.orchestrator = orchestrator;
        this.claudeGateway = claudeGateway;
        this.orchestratorProperties = orchestratorProperties;
        this.auditMemory = auditMemory;
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
        validateSource(file, gitUrl, lang);
        AuditJob job = jobs.create(lang);
        configureSource(job, file, gitUrl);
        job.submitOnce(Set.of());
        orchestrator.submit(job);
        return ResponseEntity.accepted().body(new SubmitResponse(
                job.jobId(),
                JobStatus.PENDING.value(),
                "audit submitted; use /audit/" + job.jobId() + "/logs for progress"
        ));
    }

    @PostMapping(
            path = "/audit/interfaces",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE
    )
    public InterfacePreviewResponse previewInterfaces(
            @RequestParam(required = false) MultipartFile file,
            @RequestParam(name = "git_url", required = false) String gitUrl,
            @RequestParam(defaultValue = "java") String lang
    ) throws Exception {
        validateSource(file, gitUrl, lang);
        AuditJob job = jobs.create(lang);
        try {
            configureSource(job, file, gitUrl);
            var source = sources.prepare(job);
            var interfaces = interfaceInventory.scan(source.sourceRoot())
                    .stream()
                    .map(summary -> new InterfaceOption(
                            summary.id(),
                            summary.protocol(),
                            summary.operations(),
                            summary.route(),
                            summary.className(),
                            summary.methodName(),
                            summary.filePath(),
                            summary.startLine(),
                            summary.framework(),
                            summary.securityAnnotations()
                    ))
                    .toList();
            job.setStatus(JobStatus.PENDING);
            return new InterfacePreviewResponse(
                    job.jobId(),
                    job.status().value(),
                    interfaces
            );
        } catch (Exception exception) {
            job.fail(exception.getMessage());
            logs.publish(job, "[FATAL] " + exception.getMessage());
            logs.finish(job);
            throw exception;
        }
    }

    @DeleteMapping("/audit/{jobId}/preview")
    public ResponseEntity<Void> cancelPreview(@PathVariable String jobId) {
        AuditJob job = requireJob(jobId);
        if (job.submitted()) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "submitted audit cannot be cancelled as a preview"
            );
        }
        job.fail("interface selection cancelled");
        logs.finish(job);
        return ResponseEntity.noContent().build();
    }

    @PostMapping(
            path = "/audit/{jobId}/start",
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<SubmitResponse> startSelected(
            @PathVariable String jobId,
            @RequestBody StartAuditRequest request
    ) throws Exception {
        AuditJob job = requireJob(jobId);
        if (job.projectPath() == null || !Files.isDirectory(job.projectPath())) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "source preview is not ready"
            );
        }
        Set<String> requested = request.interfaceIds().stream()
                .filter(id -> id != null && !id.isBlank())
                .collect(Collectors.toUnmodifiableSet());
        if (requested.isEmpty()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "select at least one interface"
            );
        }
        Set<String> available = interfaceInventory.scan(job.projectPath())
                .stream()
                .map(InterfaceInventoryService.InterfaceSummary::id)
                .collect(Collectors.toUnmodifiableSet());
        if (!available.containsAll(requested)) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "selected interfaces contain unknown ids"
            );
        }
        if (!job.submitOnce(requested)) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "audit has already been submitted"
            );
        }
        orchestrator.submit(job);
        return ResponseEntity.accepted().body(new SubmitResponse(
                job.jobId(),
                JobStatus.PENDING.value(),
                "selected interface audit submitted"
        ));
    }

    @GetMapping("/audit")
    public JobListResponse list() {
        return new JobListResponse(
                jobs.list().stream()
                        .filter(AuditJob::submitted)
                        .map(JobStatusResponse::from)
                        .toList()
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

    @PostMapping(
            path = "/audit/{jobId}/findings/{findingIndex}/feedback",
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public FindingFeedbackResponse findingFeedback(
            @PathVariable String jobId,
            @PathVariable int findingIndex,
            @RequestBody FindingFeedbackRequest request
    ) {
        AuditJob job = requireJob(jobId);
        if (job.status() != JobStatus.DONE && job.status() != JobStatus.FAILED) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "audit findings are not final"
            );
        }
        if (findingIndex < 0 || findingIndex >= job.findings().size()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "finding index out of range"
            );
        }
        String verdict = normalizeFeedbackVerdict(request == null
                ? null
                : request.verdict());
        if (verdict.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "verdict must be CONFIRM, FALSE_POSITIVE or NEEDS_REVIEW"
            );
        }
        auditMemory.rememberFeedback(
                job,
                findingIndex,
                job.findings().get(findingIndex),
                verdict,
                request == null ? "" : request.rationale(),
                request == null ? "" : request.reviewer()
        );
        return new FindingFeedbackResponse(
                job.jobId(),
                findingIndex,
                verdict,
                "feedback recorded as audit memory prior"
        );
    }

    @GetMapping("/audit/rule-candidates")
    public RuleCandidatesResponse ruleCandidates() {
        return new RuleCandidatesResponse(auditMemory.listRuleCandidates());
    }

    @PostMapping(
            path = "/audit/rule-candidates/{candidateId}/decision",
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public RuleDecisionResponse decideRuleCandidate(
            @PathVariable String candidateId,
            @RequestBody RuleDecisionRequest request
    ) {
        String decision = normalizeRuleDecision(request == null
                ? null
                : request.decision());
        if (decision.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "decision must be APPROVE, REJECT or DISCARD"
            );
        }
        Map<String, Object> candidate = auditMemory.decideRuleCandidate(
                candidateId,
                decision,
                request == null ? "" : request.rationale(),
                request == null ? "" : request.reviewer()
        ).orElseThrow(() -> new ResponseStatusException(
                HttpStatus.NOT_FOUND,
                "unknown rule candidate: " + candidateId
        ));
        return new RuleDecisionResponse(
                candidateId,
                candidate.getOrDefault("status", "").toString(),
                "rule decision recorded; approved rules remain priors only",
                candidate
        );
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
                "agent_available", claudeGateway.available(),
                "agent_runtime", "agentscope-java-harness",
                "intelligent_orchestrator", orchestratorProperties.enabled(),
                "analysis_engine", "jdk-ast-whitebox",
                "agent_framework", "agentscope-java",
                "agent_topology", "one-supervisor+agentscope-subagents",
                "agent_transport", "in-process-java",
                "scan_strategy", "candidate-path-whitebox"
        );
    }

    private AuditJob requireJob(String jobId) {
        return jobs.find(jobId).orElseThrow(() -> new ResponseStatusException(
                HttpStatus.NOT_FOUND,
                "job not found: " + jobId
        ));
    }

    private String normalizeFeedbackVerdict(String verdict) {
        if (verdict == null || verdict.isBlank()) {
            return "";
        }
        return switch (verdict.strip().toUpperCase(Locale.ROOT).replace('-', '_')) {
            case "CONFIRM", "CONFIRMED", "TRUE_POSITIVE" -> "CONFIRM";
            case "FALSE_POSITIVE", "SUPPRESS", "SUPPRESSED" -> "FALSE_POSITIVE";
            case "NEEDS_REVIEW", "REVIEW" -> "NEEDS_REVIEW";
            default -> "";
        };
    }

    private String normalizeRuleDecision(String decision) {
        if (decision == null || decision.isBlank()) {
            return "";
        }
        return switch (decision.strip().toUpperCase(Locale.ROOT).replace('-', '_')) {
            case "APPROVE", "APPROVED", "ACCEPT", "ACCEPTED" -> "APPROVED";
            case "REJECT", "REJECTED", "DENY", "DENIED" -> "REJECTED";
            case "DISCARD", "DISCARDED", "DISMISS", "DISMISSED" -> "DISCARDED";
            default -> "";
        };
    }

    private void configureSource(
            AuditJob job,
            MultipartFile file,
            String gitUrl
    ) throws IOException {
        boolean hasGit = gitUrl != null && !gitUrl.isBlank();
        if (hasGit) {
            job.sourceType("git");
            job.gitUrl(gitUrl.strip());
            return;
        }
        job.sourceType("zip");
        Path zipPath = sources.uploadDirectory().resolve(job.jobId() + ".zip");
        Files.copy(
                file.getInputStream(),
                zipPath,
                StandardCopyOption.REPLACE_EXISTING
        );
        job.zipPath(zipPath);
    }

    private void validateSource(
            MultipartFile file,
            String gitUrl,
            String lang
    ) {
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
    }
}
