package com.huawei.audit.agent;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.AuditProperties;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

public class ClaudeSidecarClient implements ClaudeGateway {
    private final URI baseUri;
    private final String apiToken;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public ClaudeSidecarClient(
            AuditProperties properties,
            ObjectMapper objectMapper
    ) {
        this.baseUri = URI.create(stripTrailingSlash(
                properties.claudeSidecarUrl()
        ));
        this.apiToken = properties.claudeSidecarToken();
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .build();
        this.objectMapper = objectMapper;
    }

    @Override
    public String query(
            Path workingDirectory,
            String prompt,
            Duration timeout
    ) {
        try {
            String body = objectMapper.writeValueAsString(new QueryRequest(
                    prompt,
                    workingDirectory.toAbsolutePath().normalize().toString()
            ));
            HttpResponse<String> response = httpClient.send(
                    request("/v1/query", body),
                    HttpResponse.BodyHandlers.ofString()
            );
            requireSuccess(response.statusCode(), response.body());
            return objectMapper.readTree(response.body())
                    .path("result")
                    .asText();
        } catch (IOException exception) {
            throw failure("query", exception);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw failure("query", exception);
        }
    }

    @Override
    public String supervise(
            Path workingDirectory,
            Path sourceRoot,
            String prompt,
            Map<String, AgentDef> agents,
            Consumer<String> eventConsumer
    ) {
        try {
            String body = objectMapper.writeValueAsString(new SuperviseRequest(
                    prompt,
                    workingDirectory.toAbsolutePath().normalize().toString(),
                    sourceRoot.toAbsolutePath().normalize().toString(),
                    agents != null ? agents : Map.of()
            ));
            HttpResponse<java.util.stream.Stream<String>> response =
                    httpClient.send(
                            request("/v1/supervise", body),
                            HttpResponse.BodyHandlers.ofLines()
                    );
            requireSuccess(response.statusCode(), "");
            AtomicReference<String> finalResult = new AtomicReference<>("");
            try (var lines = response.body()) {
                lines.filter(line -> !line.isBlank()).forEach(line ->
                        consumeEvent(line, finalResult, eventConsumer)
                );
            }
            if (finalResult.get().isBlank()) {
                throw new IllegalStateException(
                        "Claude sidecar returned no final result"
                );
            }
            return finalResult.get();
        } catch (IOException exception) {
            throw failure("supervise", exception);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw failure("supervise", exception);
        }
    }

    @Override
    public boolean available() {
        try {
            HttpRequest request = HttpRequest.newBuilder(
                            baseUri.resolve("/health"))
                    .timeout(Duration.ofSeconds(2))
                    .GET()
                    .build();
            HttpResponse<Void> response = httpClient.send(
                    request,
                    HttpResponse.BodyHandlers.discarding()
            );
            return response.statusCode() == 200;
        } catch (IOException exception) {
            return false;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private HttpRequest request(
            String path,
            String body
    ) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(
                        baseUri.resolve(path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (!apiToken.isBlank()) {
            builder.header("Authorization", "Bearer " + apiToken);
        }
        return builder.build();
    }

    private void consumeEvent(
            String line,
            AtomicReference<String> finalResult,
            Consumer<String> eventConsumer
    ) {
        try {
            JsonNode event = objectMapper.readTree(line);
            switch (event.path("type").asText()) {
                case "subagent_started" -> eventConsumer.accept(
                        "[subagent-start] START "
                                + event.path("agent").asText()
                                + description(event)
                );
                case "subagent_completed" -> eventConsumer.accept(
                        "[subagent-return] "
                                + event.path("status").asText().toUpperCase()
                                + " " + event.path("agent").asText()
                                + " | progress "
                                + event.path("completed").asInt() + "/"
                                + event.path("total").asInt()
                                + " | result "
                                + event.path("result_size").asText()
                                + " | preview: "
                                + event.path("preview").asText()
                );
                case "assistant_text" -> eventConsumer.accept(
                        "[supervisor] " + event.path("text").asText()
                );
                case "result" -> finalResult.set(
                        event.path("result").asText()
                );
                case "error" -> throw new IllegalStateException(
                        event.path("message").asText(
                                "Claude sidecar failed"
                        )
                );
                default -> {
                }
            }
        } catch (IOException exception) {
            throw failure("parse event", exception);
        }
    }

    private String description(JsonNode event) {
        String value = event.path("description").asText("");
        return value.isBlank() ? "" : ": " + value;
    }

    private void requireSuccess(int statusCode, String body) {
        if (statusCode < 200 || statusCode >= 300) {
            throw new IllegalStateException(
                    "Claude sidecar returned HTTP " + statusCode + ": " + body
            );
        }
    }

    private IllegalStateException failure(
            String operation,
            Exception exception
    ) {
        return new IllegalStateException(
                "Claude sidecar " + operation + " failed",
                exception
        );
    }

    private static String stripTrailingSlash(String value) {
        return value.endsWith("/")
                ? value.substring(0, value.length() - 1)
                : value;
    }

    private record QueryRequest(
            String prompt,
            @JsonProperty("working_directory") String workingDirectory
    ) { }

    private record SuperviseRequest(
            String prompt,
            @JsonProperty("working_directory") String workingDirectory,
            @JsonProperty("source_root") String sourceRoot,
            Map<String, AgentDef> agents
    ) { }
}
