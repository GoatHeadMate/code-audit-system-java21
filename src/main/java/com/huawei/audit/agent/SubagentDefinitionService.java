package com.huawei.audit.agent;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public interface SubagentDefinitionService {
    /**
     * Creates instruction files for each hunter and returns a map of
     * base-category to absolute instruction file path.
     */
    Map<String, String> materialize(Path workDirectory, List<String> hunters, Map<String, String> taskManifest)
            throws IOException;
}
