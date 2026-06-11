package com.huawei.audit.analysis.impl;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JavaSourceIndexerTest {

    @TempDir
    Path tempDir;

    @Test
    void indexesSourcesAcrossParserBatches() throws Exception {
        for (int index = 0; index < 140; index++) {
            Files.writeString(
                    tempDir.resolve("Service" + index + ".java"),
                    "class Service" + index
                            + " { void execute() { helper(); }"
                            + " void helper() { } }"
            );
        }

        SourceIndex result = new JavaSourceIndexer().build(tempDir);

        assertThat(result.methods()).hasSize(280);
        assertThat(result.parseErrors()).isEmpty();
    }
}
