package com.huawei.audit.source;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AsyncEntryPointDiscovererTest {
    @TempDir
    Path tempDir;

    @Test
    void discoversScheduledAndMessageConsumers() throws Exception {
        Files.writeString(tempDir.resolve("Jobs.java"), """
                import org.springframework.scheduling.annotation.Scheduled;
                import org.springframework.kafka.annotation.KafkaListener;

                class Jobs {
                    @Scheduled(cron = "0 * * * * *")
                    void scheduledRun() {
                    }

                    @KafkaListener(topics = "rules")
                    void consume(String payload) {
                    }
                }
                """);

        var entries = new AsyncEntryPointDiscoverer().discover(tempDir);

        assertThat(entries)
                .extracting(entry ->
                        entry.protocol() + " " + entry.methodName())
                .containsExactlyInAnyOrder(
                        "scheduled scheduledRun",
                        "message consume"
                );
    }
}
