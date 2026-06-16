package com.huawei.audit.agent.impl;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class EvidencePreparationServiceImplTest {

    @Test
    void partitionsCandidateAndStoredChunksUnderOneStrictLimit() {
        List<String> candidateChunks = List.of("candidate-1");
        List<String> storedChunks = IntStream.rangeClosed(1, 39)
                .mapToObj(index -> "stored-" + index)
                .toList();

        var batches = EvidenceBatchPlanner.partitionChunks(
                candidateChunks,
                storedChunks,
                20
        );

        assertThat(batches).hasSize(2);
        assertThat(batches)
                .allSatisfy(batch -> assertThat(
                        batch.candidateChunks().size()
                                + batch.storedChunks().size()
                ).isLessThanOrEqualTo(20));
        assertThat(batches)
                .flatExtracting(EvidenceBatchPlanner.ChunkBatch::candidateChunks)
                .containsExactlyElementsOf(candidateChunks);
        assertThat(batches)
                .flatExtracting(EvidenceBatchPlanner.ChunkBatch::storedChunks)
                .containsExactlyElementsOf(storedChunks);
    }
}
