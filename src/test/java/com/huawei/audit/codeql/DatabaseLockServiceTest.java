package com.huawei.audit.codeql;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.codeql.impl.DatabaseLockServiceImpl;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DatabaseLockServiceTest {

    @TempDir
    Path tempDir;

    @Test
    void serializesQueriesForTheSameDatabase() throws Exception {
        DatabaseLockService locks = new DatabaseLockServiceImpl();
        AtomicInteger active = new AtomicInteger();
        AtomicInteger maxActive = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var first = executor.submit(() -> lockedQuery(
                    locks, tempDir.resolve("db"), start, active, maxActive
            ));
            var second = executor.submit(() -> lockedQuery(
                    locks, tempDir.resolve("db"), start, active, maxActive
            ));
            start.countDown();
            first.get();
            second.get();
        }

        assertThat(maxActive).hasValue(1);
    }

    @Test
    void allowsDifferentDatabasesToRunConcurrently() throws Exception {
        DatabaseLockService locks = new DatabaseLockServiceImpl();
        AtomicInteger active = new AtomicInteger();
        AtomicInteger maxActive = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var first = executor.submit(() -> lockedQuery(
                    locks, tempDir.resolve("db-one"), start, active, maxActive
            ));
            var second = executor.submit(() -> lockedQuery(
                    locks, tempDir.resolve("db-two"), start, active, maxActive
            ));
            start.countDown();
            first.get();
            second.get();
        }

        assertThat(maxActive.get()).isGreaterThanOrEqualTo(2);
    }

    private Void lockedQuery(
            DatabaseLockService locks,
            Path database,
            CountDownLatch start,
            AtomicInteger active,
            AtomicInteger maxActive
    ) throws Exception {
        start.await();
        return locks.withDatabaseReadLock(database, Duration.ofSeconds(5), () -> {
            int current = active.incrementAndGet();
            maxActive.accumulateAndGet(current, Math::max);
            Thread.sleep(200);
            active.decrementAndGet();
            return null;
        });
    }
}
