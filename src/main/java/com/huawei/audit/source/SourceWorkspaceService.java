package com.huawei.audit.source;

import com.huawei.audit.domain.AuditJob;
import java.nio.file.Path;

public interface SourceWorkspaceService {
    PreparedSource prepare(AuditJob job) throws Exception;

    Path uploadDirectory();

    public record PreparedSource(Path sourceRoot, String cacheKey) { }
}
