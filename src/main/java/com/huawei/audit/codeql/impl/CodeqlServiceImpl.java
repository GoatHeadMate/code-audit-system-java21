package com.huawei.audit.codeql.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.codeql.CodeqlService;
import com.huawei.audit.codeql.DatabaseLockService;
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
import java.util.concurrent.Semaphore;
import org.springframework.stereotype.Service;

@Service
public class CodeqlServiceImpl implements CodeqlService {
    private static final int MAX_CHARS_PER_QUERY = 8_000;
    private static final int MAX_TOTAL_EVIDENCE = 30_000;

    private final AuditProperties properties;
    private final RuntimeExecutables executables;
    private final ProcessRunner processes;
    private final DatabaseLockService locks;
    private final JobLogBroker logs;
    private final ObjectMapper objectMapper;
    private final ExecutorService executor;
    private final Semaphore codeqlSlots;
    private final Path queryRoot;
    private final CodeqlQueryCache queryCache;
    private final CodeqlEvidenceCompactor evidenceCompactor;

    public CodeqlServiceImpl(
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
        this.codeqlSlots = new Semaphore(properties.codeqlParallelism());
        this.queryRoot = Path.of("codeql", "java").toAbsolutePath().normalize();
        this.queryCache = new CodeqlQueryCache(objectMapper, queryRoot);
        this.evidenceCompactor = new CodeqlEvidenceCompactor(objectMapper);
    }

    @Override
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

    @Override
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

        // Virtual threads prepare all query tasks concurrently. CodeQL evaluation is
        // serialized per database because the evaluator writes an exclusive IMB cache.
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
                JsonNode compact = evidenceCompactor.compact(
                        outcome.node(),
                        MAX_CHARS_PER_QUERY
                );
                int charCount = objectMapper.writeValueAsString(compact).length();
                if (totalChars + charCount > MAX_TOTAL_EVIDENCE) {
                    errors.put(queryName, "skipped because evidence budget was exhausted");
                } else {
                    results.put(queryName, compact);
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
                        "--threads", String.valueOf(properties.codeqlParallelism()),
                        "--ram", String.valueOf(properties.codeqlRamMb()),
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
            Path cacheFile = queryCache.cacheFile(database, hunter, query);
            JsonNode cached = queryCache.read(cacheFile);
            if (cached != null) {
                logs.publish(
                        job,
                        "[hunter:" + hunter + "] query cache hit " + queryName
                );
                return new QueryOutcome(cached, null);
            }

            int exitCode = locks.withDatabaseReadLock(
                    database,
                    properties.queryLockTimeout(),
                    () -> {
                        codeqlSlots.acquire();
                        try {
                            return runQuery(job, hunter, database, query, bqrs);
                        } finally {
                            codeqlSlots.release();
                        }
                    }
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

            JsonNode node = objectMapper.readTree(json.toFile());
            queryCache.write(cacheFile, node);
            return new QueryOutcome(node, null);
        } catch (Exception exception) {
            logs.publish(job, "[hunter:" + hunter + "] query failed: " + exception.getMessage());
            return new QueryOutcome(null, exception.getMessage());
        }
    }

    private record QueryOutcome(JsonNode node, String error) { }

}
