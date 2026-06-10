package com.huawei.audit.codeql;

import com.huawei.audit.config.AuditProperties;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.concurrent.Callable;
import org.springframework.stereotype.Component;

@Component
public class DatabaseLockService {
    private final Path lockRoot;

    public DatabaseLockService(AuditProperties properties) throws IOException {
        this.lockRoot = properties.absoluteWorkspace().resolve("query-locks");
        Files.createDirectories(lockRoot);
    }

    public <T> T withDatabaseLock(
            Path database,
            Duration timeout,
            Callable<T> action
    ) throws Exception {
        Path lockPath = lockPath(database);
        Instant deadline = Instant.now().plus(timeout);

        try (FileChannel channel = FileChannel.open(
                lockPath,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE
        )) {
            while (Instant.now().isBefore(deadline)) {
                try {
                    FileLock lock = channel.tryLock();
                    if (lock != null) {
                        try (lock) {
                            return action.call();
                        }
                    }
                } catch (OverlappingFileLockException ignored) {
                    // Another virtual thread in this JVM owns the database lock.
                }
                Thread.sleep(250);
            }
        }
        throw new IOException("timed out waiting for CodeQL database lock: " + database);
    }

    private Path lockPath(Path database) {
        String normalized = database.toAbsolutePath().normalize().toString().toLowerCase();
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(normalized.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return lockRoot.resolve(HexFormat.of().formatHex(digest, 0, 12) + ".lock");
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
