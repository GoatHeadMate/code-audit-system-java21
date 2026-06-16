package com.huawei.audit.source;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.source.impl.InterfaceInventoryServiceImpl;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class InterfaceInventoryServiceTest {
    @TempDir
    Path tempDir;

    @Test
    void listsSelectableInterfacesAndSkipsScheduledJobs() throws Exception {
        Files.writeString(tempDir.resolve("Endpoints.java"), """
                import org.springframework.web.bind.annotation.*;
                import org.springframework.scheduling.annotation.Scheduled;

                @RestController
                @RequestMapping("/api")
                class Endpoints {
                    @GetMapping("/first")
                    void first() {}

                    @PostMapping("/second")
                    void second() {}

                    @Scheduled(fixedDelay = 1000)
                    void background() {}
                }
                """);

        InterfaceInventoryService service = new InterfaceInventoryServiceImpl(
                List.of(
                        new HttpEndpointScanner(),
                        new AsyncEntryPointDiscoverer()
                )
        );

        var interfaces = service.scan(tempDir);

        assertThat(interfaces)
                .extracting(summary ->
                        summary.operations().getFirst() + " " + summary.route())
                .containsExactly("GET /api/first", "POST /api/second");
        assertThat(interfaces)
                .extracting(InterfaceInventoryService.InterfaceSummary::id)
                .doesNotHaveDuplicates()
                .allSatisfy(id -> assertThat(id).hasSize(24));
    }
}
