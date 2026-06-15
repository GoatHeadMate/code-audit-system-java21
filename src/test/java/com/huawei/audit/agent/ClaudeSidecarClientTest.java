package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.AuditProperties;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class ClaudeSidecarClientTest {

    @Test
    void sendsOneShotQueriesThroughTheSidecar() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/v1/query", exchange -> {
            byte[] bytes = "{\"result\":\"[]\"}".getBytes(
                    StandardCharsets.UTF_8
            );
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        try {
            ClaudeSidecarClient client = client(server);

            String result = client.query(
                    Path.of("workspace"),
                    "audit",
                    Duration.ofSeconds(5)
            );

            assertThat(result).isEqualTo("[]");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void streamsSupervisorEventsAndReturnsFinalResult() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/v1/supervise", exchange -> {
            String body = String.join("\n",
                    "{\"type\":\"subagent_started\","
                            + "\"agent\":\"authorization\","
                            + "\"description\":\"Review authorization paths\"}",
                    "{\"type\":\"subagent_completed\","
                            + "\"agent\":\"authorization\","
                            + "\"status\":\"done\",\"completed\":1,\"total\":1,"
                            + "\"result_size\":\"17 B\","
                            + "\"preview\":\"confirmed finding\"}",
                    "{\"type\":\"result\","
                            + "\"result\":\"{\\\"findings\\\":[]}\","
                            + "\"session_id\":\"session-1\"}"
            );
            exchange.getResponseHeaders().add(
                    "Content-Type", "application/x-ndjson"
            );
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        try {
            ClaudeSidecarClient client = client(server);
            List<String> events = new ArrayList<>();

            String result = client.supervise(
                    Path.of("workspace"),
                    Path.of("workspace", "src"),
                    "audit",
                    java.util.Map.of(),
                    events::add
            );

            assertThat(result).isEqualTo("{\"findings\":[]}");
            assertThat(events).containsExactly(
                    "[subagent-start] START authorization: "
                            + "Review authorization paths",
                    "[subagent-return] DONE authorization | progress 1/1"
                            + " | result 17 B | preview: confirmed finding"
            );
        } finally {
            server.stop(0);
        }
    }

    private ClaudeSidecarClient client(HttpServer server) {
        AuditProperties properties = new AuditProperties(
                Path.of("workspace"),
                "http://127.0.0.1:" + server.getAddress().getPort(),
                "",
                Duration.ofSeconds(5),
                2,
                15,
                Duration.ofMinutes(30)
        );
        return new ClaudeSidecarClient(properties, new ObjectMapper());
    }
}
