package com.huawei.audit.analysis.impl;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class StorageAccessClassifierTest {
    private final StorageAccessClassifier classifier =
            new StorageAccessClassifier();

    @Test
    void recognizesRepositoryAndTypedCacheAccesses() {
        assertThat(classify("save", "repository", "RuleRepository"))
                .isNotNull()
                .satisfies(access -> {
                    assertThat(access.kind()).isEqualTo("WRITE");
                    assertThat(access.storageKey())
                            .isEqualTo("RuleRepository");
                });
        assertThat(classify("get", "cache", "CaffeineCache"))
                .isNotNull()
                .satisfies(access -> {
                    assertThat(access.kind()).isEqualTo("READ");
                    assertThat(access.storageKey())
                            .isEqualTo("CaffeineCache");
                });
    }

    @Test
    void ignoresGenericCacheVariableWithoutStorageType() {
        assertThat(classify("get", "imageCache", "Map")).isNull();
        assertThat(classify("put", "requestCache", "HashMap")).isNull();
    }

    private com.huawei.audit.analysis.WhiteBoxAnalysisService.StorageAccess
            classify(String method, String receiver, String receiverType) {
        return classifier.classify(
                "Example#run",
                "Example.java",
                10,
                method,
                receiver,
                receiverType,
                receiver + "." + method + "(value)",
                "value",
                Map.of("value", "Rule")
        );
    }
}
