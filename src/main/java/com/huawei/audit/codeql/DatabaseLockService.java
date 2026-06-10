package com.huawei.audit.codeql;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.springframework.stereotype.Component;

/**
 * Intra-JVM read/write lock for CodeQL databases.
 * Multiple queries can hold concurrent read locks; database creation holds an exclusive write lock.
 * FileLock was abandoned because the JVM prohibits overlapping locks from the same process,
 * which serialized all parallel queries against the shared database.
 */
@Component
public class DatabaseLockService {
    private final ConcurrentHashMap<String, ReentrantReadWriteLock> locks = new ConcurrentHashMap<>();

    /** Exclusive lock — use for database creation/writes. */
    public <T> T withDatabaseLock(
            Path database,
            Duration timeout,
            Callable<T> action
    ) throws Exception {
        ReentrantReadWriteLock lock = lockFor(database);
        if (!lock.writeLock().tryLock(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
            throw new IOException("timed out waiting for database write lock: " + database);
        }
        try {
            return action.call();
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** Shared lock — use for read-only query execution (allows concurrent readers). */
    public <T> T withDatabaseReadLock(
            Path database,
            Duration timeout,
            Callable<T> action
    ) throws Exception {
        ReentrantReadWriteLock lock = lockFor(database);
        if (!lock.readLock().tryLock(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
            throw new IOException("timed out waiting for database read lock: " + database);
        }
        try {
            return action.call();
        } finally {
            lock.readLock().unlock();
        }
    }

    private ReentrantReadWriteLock lockFor(Path database) {
        String key = database.toAbsolutePath().normalize().toString().toLowerCase();
        return locks.computeIfAbsent(key, k -> new ReentrantReadWriteLock());
    }
}
