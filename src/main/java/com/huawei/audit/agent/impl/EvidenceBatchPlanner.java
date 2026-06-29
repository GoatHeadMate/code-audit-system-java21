package com.huawei.audit.agent.impl;

import java.util.ArrayList;
import java.util.List;

final class EvidenceBatchPlanner {
    private EvidenceBatchPlanner() {
    }

    static List<ChunkBatch> partitionChunks(
            List<String> candidateChunks,
            List<String> storedChunks,
            List<String> endpointChunks,
            int maxChunks
    ) {
        if (maxChunks <= 0) {
            throw new IllegalArgumentException("maxChunks must be positive");
        }
        List<TaggedChunk> combined = new ArrayList<>(
                candidateChunks.size() + storedChunks.size()
                        + endpointChunks.size()
        );
        candidateChunks.forEach(path ->
                combined.add(new TaggedChunk(path, ChunkKind.CANDIDATE)));
        storedChunks.forEach(path ->
                combined.add(new TaggedChunk(path, ChunkKind.STORED)));
        endpointChunks.forEach(path ->
                combined.add(new TaggedChunk(path, ChunkKind.ENDPOINT)));

        List<ChunkBatch> batches = new ArrayList<>();
        for (int start = 0; start < combined.size(); start += maxChunks) {
            int end = Math.min(start + maxChunks, combined.size());
            List<String> candidateBatch = new ArrayList<>();
            List<String> storedBatch = new ArrayList<>();
            List<String> endpointBatch = new ArrayList<>();
            for (TaggedChunk chunk : combined.subList(start, end)) {
                switch (chunk.kind()) {
                    case CANDIDATE -> candidateBatch.add(chunk.path());
                    case STORED -> storedBatch.add(chunk.path());
                    case ENDPOINT -> endpointBatch.add(chunk.path());
                }
            }
            batches.add(new ChunkBatch(
                    List.copyOf(candidateBatch),
                    List.copyOf(storedBatch),
                    List.copyOf(endpointBatch)
            ));
        }
        return List.copyOf(batches);
    }

    static int proportionalItemCount(
            int totalItems,
            int totalChunks,
            int chunkOffset,
            int batchChunks
    ) {
        if (totalItems == 0 || totalChunks == 0 || batchChunks == 0) {
            return 0;
        }
        int endOffset = chunkOffset + batchChunks;
        int before = (int) ((long) totalItems * chunkOffset / totalChunks);
        int after = (int) ((long) totalItems * endOffset / totalChunks);
        return after - before;
    }

    record ChunkBatch(
            List<String> candidateChunks,
            List<String> storedChunks,
            List<String> endpointChunks
    ) { }

    private enum ChunkKind {
        CANDIDATE,
        STORED,
        ENDPOINT
    }

    private record TaggedChunk(String path, ChunkKind kind) { }
}
