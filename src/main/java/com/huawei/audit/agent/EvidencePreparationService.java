package com.huawei.audit.agent;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.codeql.CodeqlService;
import com.huawei.audit.config.AuditProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.job.JobLogBroker;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import org.springframework.stereotype.Component;

@Component
public class EvidencePreparationService {
    private final CodeqlService codeql;
    private final ObjectMapper objectMapper;
    private final ExecutorService executor;
    private final JobLogBroker logs;
    private final Semaphore preparationSlots;

    public EvidencePreparationService(
            CodeqlService codeql,
            ObjectMapper objectMapper,
            ExecutorService executor,
            JobLogBroker logs,
            AuditProperties properties
    ) {
        this.codeql = codeql;
        this.objectMapper = objectMapper;
        this.executor = executor;
        this.logs = logs;
        this.preparationSlots = new Semaphore(
                properties.maxConcurrentHunters()
        );
    }

    public Map<String, String> prepare(
            AuditJob job,
            Path database,
            List<String> hunters
    ) throws Exception {
        Path evidenceDirectory = job.workDir().resolve("evidence");
        Files.createDirectories(evidenceDirectory);

        List<CompletableFuture<Map.Entry<String, String>>> futures = hunters.stream()
                .map(hunter -> CompletableFuture.supplyAsync(
                        () -> prepareHunter(job, database, evidenceDirectory, hunter),
                        executor
                ))
                .toList();

        Map<String, String> manifest = new LinkedHashMap<>();
        for (CompletableFuture<Map.Entry<String, String>> future : futures) {
            Map.Entry<String, String> entry = future.join();
            manifest.put(entry.getKey(), entry.getValue());
        }
        Files.writeString(
                evidenceDirectory.resolve("manifest.json"),
                objectMapper.writerWithDefaultPrettyPrinter()
                        .writeValueAsString(manifest)
        );
        return manifest;
    }

    private Map.Entry<String, String> prepareHunter(
            AuditJob job,
            Path database,
            Path evidenceDirectory,
            String hunter
    ) {
        Path output = evidenceDirectory.resolve(hunter + ".json");
        boolean acquired = false;
        try {
            preparationSlots.acquire();
            acquired = true;
            var evidence = codeql.collectEvidence(job, hunter, database);
            Files.writeString(
                    output,
                    objectMapper.writerWithDefaultPrettyPrinter()
                            .writeValueAsString(Map.of(
                                    "hunter", hunter,
                                    "results", evidence.results(),
                                    "errors", evidence.errors()
                            ))
            );
        } catch (Exception exception) {
            if (exception instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            logs.publish(
                    job,
                    "[evidence:" + hunter + "] failed: " + exception.getMessage()
            );
            try {
                Files.writeString(
                        output,
                        objectMapper.writeValueAsString(Map.of(
                                "hunter", hunter,
                                "results", Map.of(),
                                "errors", Map.of("collection", exception.getMessage())
                        ))
                );
            } catch (Exception writeFailure) {
                throw new IllegalStateException(writeFailure);
            }
        } finally {
            if (acquired) {
                preparationSlots.release();
            }
        }
        return Map.entry(hunter, output.toAbsolutePath().normalize().toString());
    }
}
