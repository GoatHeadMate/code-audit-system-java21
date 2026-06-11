package com.huawei.audit.job;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.domain.AuditJob;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

@ExtendWith(OutputCaptureExtension.class)
class JobLogBrokerTest {

    @Test
    void mirrorsAuditProgressToBackendLog(CapturedOutput output) {
        JobLogBroker broker = new JobLogBroker();
        AuditJob job = new AuditJob("abc123", "java");

        broker.publish(job, "[whitebox] indexing source in bounded batches");

        assertThat(output)
                .contains(
                        "[audit:abc123] "
                                + "[whitebox] indexing source in bounded batches"
                );
        assertThat(job.logHistory())
                .containsExactly(
                        "[whitebox] indexing source in bounded batches"
                );
    }
}
