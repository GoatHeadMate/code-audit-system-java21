package com.huawei.audit.source;

import com.huawei.audit.config.AuditProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.domain.JobStatus;
import com.huawei.audit.job.JobLogBroker;
import com.huawei.audit.process.ProcessResult;
import com.huawei.audit.process.ProcessRunner;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.springframework.stereotype.Component;

@Component
public class SourceWorkspaceService {
    private final AuditProperties properties;
    private final ProcessRunner processRunner;
    private final JobLogBroker logs;

    public SourceWorkspaceService(
            AuditProperties properties,
            ProcessRunner processRunner,
            JobLogBroker logs
    ) throws IOException {
        this.properties = properties;
        this.processRunner = processRunner;
        this.logs = logs;
        Files.createDirectories(uploadDirectory());
    }

    public PreparedSource prepare(AuditJob job) throws Exception {
        Path workDir = properties.absoluteWorkspace().resolve("audit_" + job.jobId());
        Path projectDir = workDir.resolve("project");
        Files.createDirectories(projectDir);
        job.workDir(workDir);
        logs.publish(job, "work_dir: " + workDir);
        job.setStatus(JobStatus.CLONING);

        String cacheKey;
        if ("git".equals(job.sourceType())) {
            cloneRepository(job, projectDir);
            cacheKey = sha256Text("git:" + job.gitUrl() + "@" + gitHead(projectDir));
        } else {
            cacheKey = sha256(job.zipPath());
            logs.publish(job, "extracting zip: " + job.zipPath());
            extractZip(job.zipPath(), projectDir);
            Files.deleteIfExists(job.zipPath());
        }

        Path sourceRoot = singleChildDirectory(projectDir);
        job.projectPath(sourceRoot);
        logs.publish(job, "source ready: " + sourceRoot);
        return new PreparedSource(sourceRoot, cacheKey.substring(0, Math.min(16, cacheKey.length())));
    }

    public Path uploadDirectory() {
        return properties.absoluteWorkspace().resolve("uploads");
    }

    private void cloneRepository(AuditJob job, Path projectDir) throws Exception {
        logs.publish(job, "git clone " + job.gitUrl());
        ProcessResult result = processRunner.run(
                java.util.List.of(
                        "git", "clone", "--depth=1", job.gitUrl(), projectDir.toString()
                ),
                properties.absoluteWorkspace(),
                Map.of(),
                Duration.ofMinutes(15),
                line -> logs.publish(job, "[git] " + line)
        );
        if (result.exitCode() != 0) {
            throw new IOException("git clone failed with exit " + result.exitCode());
        }
    }

    private String gitHead(Path projectDir) throws Exception {
        ProcessResult result = processRunner.run(
                java.util.List.of("git", "rev-parse", "HEAD"),
                projectDir,
                Map.of(),
                Duration.ofMinutes(1),
                ignored -> { }
        );
        if (result.exitCode() != 0 || result.output().isEmpty()) {
            throw new IOException("unable to resolve git HEAD");
        }
        return result.output().getFirst().trim();
    }

    private String sha256(Path file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = new DigestInputStream(Files.newInputStream(file), digest)) {
            input.transferTo(OutputStream.nullOutputStream());
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private String sha256Text(String value) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return HexFormat.of().formatHex(
                digest.digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8))
        );
    }

    private void extractZip(Path zipFile, Path destination) throws IOException {
        try (ZipInputStream zip = new ZipInputStream(Files.newInputStream(zipFile))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                Path target = destination.resolve(entry.getName()).normalize();
                if (!target.startsWith(destination)) {
                    throw new IOException("zip entry escapes destination: " + entry.getName());
                }
                if (entry.isDirectory()) {
                    Files.createDirectories(target);
                } else {
                    Files.createDirectories(target.getParent());
                    Files.copy(zip, target, StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }
    }

    private Path singleChildDirectory(Path root) throws IOException {
        try (var children = Files.list(root)) {
            var entries = children.toList();
            return entries.size() == 1 && Files.isDirectory(entries.getFirst())
                    ? entries.getFirst()
                    : root;
        }
    }

    public record PreparedSource(Path sourceRoot, String cacheKey) { }
}
