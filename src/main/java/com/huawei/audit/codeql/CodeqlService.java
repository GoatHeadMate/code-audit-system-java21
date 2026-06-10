package com.huawei.audit.codeql;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.AuditProperties;
import com.huawei.audit.config.RuntimeExecutables;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.domain.JobStatus;
import com.huawei.audit.job.JobLogBroker;
import com.huawei.audit.process.ProcessResult;
import com.huawei.audit.process.ProcessRunner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import org.springframework.stereotype.Component;

@Component
public class CodeqlService {
    private static final int MAX_CHARS_PER_QUERY = 8_000;
    private static final int MAX_TOTAL_EVIDENCE = 30_000;

    private final AuditProperties properties;
    private final RuntimeExecutables executables;
    private final ProcessRunner processes;
    private final DatabaseLockService locks;
    private final JobLogBroker logs;
    private final ObjectMapper objectMapper;
    private final ExecutorService executor;
    private final Path queryRoot;

    public CodeqlService(
            AuditProperties properties,
            RuntimeExecutables executables,
            ProcessRunner processes,
            DatabaseLockService locks,
            JobLogBroker logs,
            ObjectMapper objectMapper,
            ExecutorService executor
    ) {
        this.properties = properties;
        this.executables = executables;
        this.processes = processes;
        this.locks = locks;
        this.logs = logs;
        this.objectMapper = objectMapper;
        this.executor = executor;
        this.queryRoot = Path.of("codeql", "java").toAbsolutePath().normalize();
    }

    public Path ensureDatabase(
            AuditJob job,
            Path sourceRoot,
            String cacheKey
    ) throws Exception {
        job.setStatus(JobStatus.BUILDING_DB);
        Path database = properties.absoluteWorkspace()
                .resolve("db_cache")
                .resolve(cacheKey)
                .resolve("codeql-db");
        Path cacheMarker = database.getParent().resolve("meta.json");
        Files.createDirectories(database.getParent());

        if (Files.exists(database.resolve("codeql-database.yml"))
                && Files.exists(cacheMarker)) {
            logs.publish(job, "[cache hit] reuse CodeQL database key=" + cacheKey);
            job.dbPath(database);
            return database;
        }

        locks.withDatabaseLock(database, properties.queryLockTimeout(), () -> {
            if (Files.exists(database.resolve("codeql-database.yml"))
                    && Files.exists(cacheMarker)) {
                return database;
            }
            logs.publish(job, "building CodeQL database lang=" + job.lang() + " mode=none");
            ProcessResult result = processes.run(
                    List.of(
                            executables.codeql(),
                            "database", "create", database.toString(),
                            "--language=" + job.lang(),
                            "--source-root=" + sourceRoot,
                            "--build-mode=none",
                            "--overwrite"
                    ),
                    Path.of("").toAbsolutePath(),
                    Map.of(),
                    Duration.ofMinutes(30),
                    line -> logs.publish(job, "[codeql] " + line)
            );
            if (result.exitCode() != 0) {
                throw new IOException(
                        "CodeQL database create failed with exit " + result.exitCode()
                );
            }
            Files.writeString(
                    cacheMarker,
                    objectMapper.writeValueAsString(Map.of(
                            "cache_key", cacheKey,
                            "language", job.lang(),
                            "completed_at", java.time.Instant.now().toString()
                    ))
            );
            return database;
        });

        job.dbPath(database);
        logs.publish(job, "CodeQL database ready -> " + database);
        return database;
    }

    public Evidence collectEvidence(
            AuditJob job,
            String hunter,
            Path database
    ) throws Exception {
        Path hunterQueries = queryRoot.resolve(hunter);
        if (!Files.isDirectory(hunterQueries)) {
            return new Evidence(Map.of(), Map.of("queries", "missing " + hunterQueries));
        }

        List<Path> queries;
        try (var stream = Files.list(hunterQueries)) {
            queries = stream
                    .filter(path -> path.getFileName().toString().endsWith(".ql"))
                    .sorted(Comparator.comparing(path -> path.getFileName().toString()))
                    .toList();
        }

        Path outputDir = Files.createTempDirectory(
                properties.absoluteWorkspace(),
                hunter + "-"
        );

        // Launch all queries in parallel via virtual threads; each holds a shared read lock.
        List<CompletableFuture<QueryOutcome>> futures = queries.stream()
                .map(query -> CompletableFuture.supplyAsync(
                        () -> runQueryTask(job, hunter, database, query, outputDir),
                        executor
                ))
                .toList();

        // Aggregate in query-sorted order to keep evidence deterministic.
        Map<String, JsonNode> results = new LinkedHashMap<>();
        Map<String, String> errors = new LinkedHashMap<>();
        int totalChars = 0;
        for (int i = 0; i < queries.size(); i++) {
            String queryName = queries.get(i).getFileName().toString();
            QueryOutcome outcome = futures.get(i).join();
            if (outcome.error() != null) {
                errors.put(queryName, outcome.error());
            } else {
                int charCount = Math.min(
                        objectMapper.writeValueAsString(outcome.node()).length(),
                        MAX_CHARS_PER_QUERY
                );
                if (totalChars + charCount > MAX_TOTAL_EVIDENCE) {
                    errors.put(queryName, "skipped because evidence budget was exhausted");
                } else {
                    results.put(queryName, outcome.node());
                    totalChars += charCount;
                }
            }
        }
        return new Evidence(results, errors);
    }

    private int runQuery(
            AuditJob job,
            String hunter,
            Path database,
            Path query,
            Path bqrs
    ) throws Exception {
        logs.publish(job, "[hunter:" + hunter + "] CodeQL " + query.getFileName());
        ProcessResult result = processes.run(
                List.of(
                        executables.codeql(),
                        "query", "run",
                        "--database", database.toString(),
                        "--output", bqrs.toString(),
                        query.toString()
                ),
                Path.of("").toAbsolutePath(),
                Map.of(),
                Duration.ofMinutes(15),
                line -> logs.publish(job, "[hunter:" + hunter + "][codeql] " + line)
        );
        return result.exitCode();
    }

    private QueryOutcome runQueryTask(
            AuditJob job,
            String hunter,
            Path database,
            Path query,
            Path outputDir
    ) {
        String queryName = query.getFileName().toString();
        Path bqrs = outputDir.resolve(queryName + ".bqrs");
        Path json = outputDir.resolve(queryName + ".json");
        try {
            int exitCode = locks.withDatabaseReadLock(
                    database,
                    properties.queryLockTimeout(),
                    () -> runQuery(job, hunter, database, query, bqrs)
            );
            if (exitCode != 0 || !Files.exists(bqrs)) {
                return new QueryOutcome(null, "query failed with exit " + exitCode);
            }

            ProcessResult decode = processes.run(
                    List.of(
                            executables.codeql(),
                            "bqrs", "decode", bqrs.toString(),
                            "--format=json",
                            "--output", json.toString()
                    ),
                    Path.of("").toAbsolutePath(),
                    Map.of(),
                    Duration.ofMinutes(5),
                    line -> logs.publish(job, "[hunter:" + hunter + "][decode] " + line)
            );
            if (decode.exitCode() != 0 || !Files.exists(json)) {
                return new QueryOutcome(null, "decode failed with exit " + decode.exitCode());
            }

            return new QueryOutcome(objectMapper.readTree(json.toFile()), null);
        } catch (Exception exception) {
            logs.publish(job, "[hunter:" + hunter + "] query failed: " + exception.getMessage());
            return new QueryOutcome(null, exception.getMessage());
        }
    }

    private record QueryOutcome(JsonNode node, String error) { }

    public record Evidence(Map<String, JsonNode> results, Map<String, String> errors) {
        public boolean allFailed() {
            return results.isEmpty() && !errors.isEmpty();
        }
    }
}
