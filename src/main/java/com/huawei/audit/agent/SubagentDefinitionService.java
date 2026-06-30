package com.huawei.audit.agent;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public interface SubagentDefinitionService {
    /**
     * Materializes one AgentScope Skill per hunter category under
     * {@code workDirectory/skills/} and returns a map of base-category
     * to skill name (e.g. {@code sql_injection -> audit-sql-injection}).
     */
    Map<String, String> materialize(Path workDirectory, List<String> hunters, Map<String, String> taskManifest)
            throws IOException;
}
