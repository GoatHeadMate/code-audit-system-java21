package com.huawei.audit.codeql.impl;

import com.huawei.audit.codeql.DatabaseLockService;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.stereotype.Service;

/**
 * Intra-JVM exclusive locking for operations that touch a CodeQL database.
 */
@Service
public class DatabaseLockServiceImpl implements DatabaseLockService {
    private final ConcurrentHashMap<String, ReentrantLock> locks =
            new ConcurrentHashMap<>();

    @Override
    public <T> T withDatabaseLock(
            Path database,
            Duration timeout,
            Callable<T> action
    ) throws Exception {
        return withExclusiveLock(database, timeout, action);
    }

    @Override
    public <T> T withDatabaseReadLock(
            Path database,
            Duration timeout,
            Callable<T> action
    ) throws Exception {
        return withExclusiveLock(database, timeout, action);
    }

    private <T> T withExclusiveLock(
            Path database,
            Duration timeout,
            Callable<T> action
    ) throws Exception {
        ReentrantLock lock = lockFor(database);
        if (!lock.tryLock(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
            throw new IOException(
                    "timed out waiting for database lock: " + database
            );
        }
        try {
            return action.call();
        } finally {
            lock.unlock();
        }
    }

    private ReentrantLock lockFor(Path database) {
        String key = database.toAbsolutePath()
                .normalize()
                .toString()
                .toLowerCase();
        return locks.computeIfAbsent(key, ignored -> new ReentrantLock());
    }
}
