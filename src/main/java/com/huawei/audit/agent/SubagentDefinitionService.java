package com.huawei.audit.agent;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public interface SubagentDefinitionService {
    void materialize(Path workDirectory, List<String> hunters) throws IOException;
}
