package com.huawei.audit.source;

import java.nio.file.Path;
import java.util.List;

public interface InterfaceInventoryService {
    List<InterfaceSummary> scan(Path sourceRoot) throws Exception;

    record InterfaceSummary(
            String id,
            String protocol,
            List<String> operations,
            String route,
            String className,
            String methodName,
            String filePath,
            int startLine,
            String framework,
            List<String> securityAnnotations
    ) { }
}
