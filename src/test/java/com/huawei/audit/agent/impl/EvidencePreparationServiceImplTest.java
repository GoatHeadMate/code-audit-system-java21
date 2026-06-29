package com.huawei.audit.agent.impl;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class EvidencePreparationServiceImplTest {

    @Test
    void partitionsCandidateStoredAndEndpointChunksUnderOneStrictLimit() {
        List<String> candidateChunks = List.of("candidate-1");
        List<String> storedChunks = IntStream.rangeClosed(1, 39)
                .mapToObj(index -> "stored-" + index)
                .toList();
        List<String> endpointChunks = List.of("endpoint-1", "endpoint-2");

        var batches = EvidenceBatchPlanner.partitionChunks(
                candidateChunks,
                storedChunks,
                endpointChunks,
                20
        );

        assertThat(batches).hasSize(3);
        assertThat(batches)
                .allSatisfy(batch -> assertThat(
                        batch.candidateChunks().size()
                                + batch.storedChunks().size()
                                + batch.endpointChunks().size()
                ).isLessThanOrEqualTo(20));
        assertThat(batches)
                .flatExtracting(EvidenceBatchPlanner.ChunkBatch::candidateChunks)
                .containsExactlyElementsOf(candidateChunks);
        assertThat(batches)
                .flatExtracting(EvidenceBatchPlanner.ChunkBatch::storedChunks)
                .containsExactlyElementsOf(storedChunks);
        assertThat(batches)
                .flatExtracting(EvidenceBatchPlanner.ChunkBatch::endpointChunks)
                .containsExactlyElementsOf(endpointChunks);
    }
}
