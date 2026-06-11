package com.huawei.audit.source;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class HttpEndpointScannerTest {

    @TempDir
    Path tempDir;

    @Test
    void scansSpringAndHuaweiRoaEndpointsAndRceHints() throws Exception {
        Path spring = tempDir.resolve("SpringController.java");
        Files.writeString(spring, """
                import org.springframework.web.bind.annotation.*;

                @RestController
                @RequestMapping("/api")
                class SpringController {
                    @PostMapping("/run")
                    public String run(@RequestBody String command) {
                        return command;
                    }
                }
                """);
        Path roa = tempDir.resolve("RoaService.java");
        Files.writeString(roa, """
                import com.huawei.bsp.roa.annotation.POST;
                import com.huawei.bsp.roa.annotation.Path;

                @Path(value={"/dp"})
                class RoaService {
                    @POST
                    @Path(value={"/execute"})
                    public void execute(String command) throws Exception {
                        new ProcessBuilder("/bin/bash", "-c", command).start();
                    }
                }
                """);

        var result = new HttpEndpointScanner().scan(tempDir);

        assertThat(result.endpoints())
                .extracting(endpoint -> endpoint.httpMethods().getFirst()
                        + " " + endpoint.httpPath())
                .containsExactlyInAnyOrder(
                        "POST /api/run",
                        "POST /dp/execute"
                );
        assertThat(result.sourceHints())
                .anySatisfy(hint -> {
                    assertThat(hint.category()).isEqualTo("COMMAND_EXECUTION");
                    assertThat(hint.filePath()).isEqualTo("RoaService.java");
                });
    }
}
