package com.huawei.audit.analysis;

import java.nio.file.Path;
import java.util.List;

public interface EntryPointDiscoverer {

    String id();

    List<DiscoveredEntryPoint> discover(Path sourceRoot) throws Exception;

    record DiscoveredEntryPoint(
            String protocol,
            List<String> operations,
            String route,
            String className,
            String methodName,
            String filePath,
            int startLine,
            String framework,
            List<String> securityAnnotations,
            String discoverySource,
            String confidence
    ) { }
}
