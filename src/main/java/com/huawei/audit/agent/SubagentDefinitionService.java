package com.huawei.audit.agent;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public interface SubagentDefinitionService {
    void materialize(Path workDirectory, List<String> hunters, Map<String, String> manifest)
            throws IOException;
}
