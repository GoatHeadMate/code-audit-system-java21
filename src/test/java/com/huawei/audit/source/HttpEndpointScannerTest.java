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

    @Test
    void keepsRelativePathsAndExcludesProduces() throws Exception {
        Files.writeString(tempDir.resolve("RelController.java"), """
                import org.springframework.web.bind.annotation.*;

                @RestController
                @RequestMapping("api")
                class RelController {
                    @GetMapping(value = "users", produces = "application/json")
                    String list() { return ""; }
                }
                """);

        var result = new HttpEndpointScanner().scan(tempDir);

        assertThat(result.endpoints())
                .extracting(endpoint -> endpoint.httpMethods().getFirst()
                        + " " + endpoint.httpPath())
                .containsExactly("GET /api/users");
    }

    @Test
    void doesNotLetCommentsPolluteClassName() throws Exception {
        Files.writeString(tempDir.resolve("CommentController.java"), """
                import org.springframework.web.bind.annotation.*;

                @RestController
                @RequestMapping("/c")
                class CommentController {
                    // returns the user record for the given interface class
                    @GetMapping("/u")
                    String u() { return ""; }
                }
                """);

        var result = new HttpEndpointScanner().scan(tempDir);

        assertThat(result.endpoints()).singleElement().satisfies(endpoint -> {
            assertThat(endpoint.className()).isEqualTo("CommentController");
            assertThat(endpoint.httpPath()).isEqualTo("/c/u");
        });
    }

    @Test
    void keepsInnerClassMappingsSeparate() throws Exception {
        Files.writeString(tempDir.resolve("Outer.java"), """
                import org.springframework.web.bind.annotation.*;

                @RestController
                @RequestMapping("/outer")
                class Outer {
                    @GetMapping("/a") String a() { return ""; }

                    @RestController
                    @RequestMapping("/inner")
                    static class Inner {
                        @GetMapping("/b") String b() { return ""; }
                    }
                }
                """);

        var result = new HttpEndpointScanner().scan(tempDir);

        assertThat(result.endpoints())
                .extracting(HttpEndpointScanner.Endpoint::httpPath)
                .containsExactlyInAnyOrder("/outer/a", "/inner/b");
    }

    @Test
    void discoversInterfaceEndpointsWithoutBody() throws Exception {
        Files.writeString(tempDir.resolve("Api.java"), """
                import org.springframework.web.bind.annotation.*;

                @RequestMapping("/api")
                interface Api {
                    @GetMapping("/ping") String ping();
                }
                """);

        var result = new HttpEndpointScanner().scan(tempDir);

        assertThat(result.endpoints())
                .extracting(HttpEndpointScanner.Endpoint::httpPath)
                .containsExactly("/api/ping");
    }

    @Test
    void discoversRecordController() throws Exception {
        Files.writeString(tempDir.resolve("RecController.java"), """
                import org.springframework.web.bind.annotation.*;

                @RestController
                @RequestMapping("/rec")
                record RecController(String service) {
                    @GetMapping("/ping") String ping() { return ""; }
                }
                """);

        var result = new HttpEndpointScanner().scan(tempDir);

        assertThat(result.endpoints())
                .extracting(HttpEndpointScanner.Endpoint::httpPath)
                .containsExactly("/rec/ping");
    }

    @Test
    void discoversEnumController() throws Exception {
        Files.writeString(tempDir.resolve("EnumController.java"), """
                import org.springframework.web.bind.annotation.*;

                @RestController
                @RequestMapping("/enum")
                enum EnumController {
                    INSTANCE;

                    @GetMapping("/ping") String ping() { return ""; }
                }
                """);

        var result = new HttpEndpointScanner().scan(tempDir);

        assertThat(result.endpoints())
                .extracting(HttpEndpointScanner.Endpoint::httpPath)
                .containsExactly("/enum/ping");
    }

}
