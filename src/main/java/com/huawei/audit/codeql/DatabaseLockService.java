package com.huawei.audit.codeql;

import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.Callable;

public interface DatabaseLockService {
    <T> T withDatabaseLock(
            Path database,
            Duration timeout,
            Callable<T> action
    ) throws Exception;

    <T> T withDatabaseReadLock(
            Path database,
            Duration timeout,
            Callable<T> action
    ) throws Exception;
}
