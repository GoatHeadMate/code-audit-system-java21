package com.huawei.audit.analysis;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.analysis.impl.WhiteBoxAnalysisServiceImpl;
import com.huawei.audit.source.AsyncEntryPointDiscoverer;
import com.huawei.audit.source.HttpEndpointScanner;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class WhiteBoxAnalysisServiceTest {

    @TempDir
    Path tempDir;

    @Test
    void buildsCandidatePathAcrossInterfaceImplementationAndService()
            throws Exception {
        Files.writeString(tempDir.resolve("RunController.java"), """
                import org.springframework.web.bind.annotation.*;

                @RestController
                @RequestMapping("/api")
                class RunController {
                    private Runner runner;

                    @PostMapping("/run")
                    String run(@RequestBody String command) {
                        return runner.run(command);
                    }
                }
                """);
        Files.writeString(tempDir.resolve("Runner.java"), """
                interface Runner {
                    String run(String command);
                }
                """);
        Files.writeString(tempDir.resolve("RunnerImpl.java"), """
                class RunnerImpl implements Runner {
                    private Worker worker;

                    public String run(String command) {
                        return worker.execute(command);
                    }
                }
                """);
        Files.writeString(tempDir.resolve("Worker.java"), """
                class Worker {
                    String execute(String command) {
                        try {
                            new ProcessBuilder("/bin/bash", "-c", command).start();
                            return "ok";
                        } catch (Exception exception) {
                            return "failed";
                        }
                    }
                }
                """);

        var result = new WhiteBoxAnalysisServiceImpl(
                List.of(new HttpEndpointScanner())
        ).analyze(tempDir);

        assertThat(result.coverage().discoveredEntryPoints()).isEqualTo(1);
        assertThat(result.coverage().boundEntryPoints()).isEqualTo(1);
        assertThat(result.candidatePaths())
                .anySatisfy(candidate -> {
                    assertThat(candidate.entryPoint().path()).isEqualTo("/api/run");
                    assertThat(candidate.sink().category())
                            .isEqualTo("COMMAND_EXECUTION");
                    assertThat(candidate.methodPath())
                            .extracting(step -> step.className() + "." + step.methodName())
                            .containsExactly(
                                    "RunController.run",
                                    "RunnerImpl.run",
                                    "Worker.execute"
                            );
                });
    }

    @Test
    void correlatesStoredMvelRceAcrossHttpWriteAndScheduledRead()
            throws Exception {
        Files.writeString(tempDir.resolve("RuleController.java"), """
                import org.springframework.web.bind.annotation.*;

                @RestController
                class RuleController {
                    private RuleService service;

                    @PostMapping("/rules")
                    void save(@RequestBody Rule rule) {
                        service.save(rule);
                    }
                }
                """);
        Files.writeString(tempDir.resolve("RuleService.java"), """
                class RuleService {
                    private RuleRepository repository;

                    void save(Rule rule) {
                        repository.save(rule);
                    }
                }
                """);
        Files.writeString(tempDir.resolve("RuleJob.java"), """
                import org.springframework.scheduling.annotation.Scheduled;

                class RuleJob {
                    private RuleRepository repository;

                    @Scheduled(fixedDelay = 1000)
                    void execute() {
                        Rule rule = repository.findFirst();
                        String expression = "method=" + rule.getMethod();
                        MVEL.executeExpression(expression);
                    }
                }
                """);
        Files.writeString(tempDir.resolve("RuleRepository.java"), """
                interface RuleRepository {
                    Rule save(Rule rule);
                    Rule findFirst();
                }
                """);
        Files.writeString(tempDir.resolve("Rule.java"), """
                class Rule {
                    String method;
                    String getMethod() { return method; }
                }
                """);

        var result = new WhiteBoxAnalysisServiceImpl(List.of(
                new HttpEndpointScanner(),
                new AsyncEntryPointDiscoverer()
        )).analyze(tempDir);

        assertThat(result.storageAccesses())
                .extracting(access ->
                        access.kind() + " " + access.storageKey())
                .contains("WRITE RuleRepository", "READ RuleRepository");
        assertThat(result.storedCandidates())
                .singleElement()
                .satisfies(candidate -> {
                    assertThat(candidate.writePath().entryPoint().path())
                            .isEqualTo("/rules");
                    assertThat(candidate.executionPath().entryPoint().protocol())
                            .isEqualTo("scheduled");
                    assertThat(candidate.executionPath().sink().api())
                            .contains("MVEL.executeExpression");
                    assertThat(candidate.storageKey())
                            .isEqualTo("RuleRepository");
                    assertThat(candidate.correlationConfidence())
                            .isEqualTo("MEDIUM");
                });
    }

    @Test
    void correlatesMessagePoisoningWithScheduledMvelExecution()
            throws Exception {
        Files.writeString(tempDir.resolve("RuleConsumer.java"), """
                import org.springframework.kafka.annotation.KafkaListener;

                class RuleConsumer {
                    private RuleRepository repository;

                    @KafkaListener(topics = "rules")
                    void consume(Rule rule) {
                        repository.save(rule);
                    }
                }
                """);
        Files.writeString(tempDir.resolve("RuleJob.java"), """
                import org.springframework.scheduling.annotation.Scheduled;

                class RuleJob {
                    private RuleRepository repository;

                    @Scheduled(fixedDelay = 1000)
                    void execute() {
                        Rule rule = repository.findFirst();
                        MVEL.executeExpression(rule.expression);
                    }
                }
                """);
        Files.writeString(tempDir.resolve("RuleRepository.java"), """
                interface RuleRepository {
                    Rule save(Rule rule);
                    Rule findFirst();
                }
                """);
        Files.writeString(tempDir.resolve("Rule.java"), """
                class Rule {
                    String expression;
                }
                """);

        var result = new WhiteBoxAnalysisServiceImpl(
                List.of(new AsyncEntryPointDiscoverer())
        ).analyze(tempDir);

        assertThat(result.storedCandidates())
                .singleElement()
                .satisfies(candidate -> {
                    assertThat(
                            candidate.writePath().entryPoint().protocol()
                    ).isEqualTo("message");
                    assertThat(
                            candidate.executionPath().entryPoint().protocol()
                    ).isEqualTo("scheduled");
                    assertThat(candidate.storageKey())
                            .isEqualTo("RuleRepository");
                });
    }

    @Test
    void followsExecutorAndMethodReferenceDispatchToCommandSinks()
            throws Exception {
        Files.writeString(tempDir.resolve("TaskController.java"), """
                import org.springframework.web.bind.annotation.*;

                @RestController
                class TaskController {
                    private TaskCreator creator;

                    @PostMapping("/tasks")
                    void create(@RequestBody String input) {
                        creator.create(input);
                    }
                }
                """);
        Files.writeString(tempDir.resolve("TaskCreator.java"), """
                class TaskCreator {
                    void create(String input) {
                        CollectionTask task = new CollectionTask(input);
                        TaskManager.instance().registerTask(task);
                    }
                }
                """);
        Files.writeString(tempDir.resolve("TaskManager.java"), """
                import java.util.concurrent.ExecutorService;

                class TaskManager {
                    private static ExecutorService executor;
                    static TaskManager instance() { return null; }

                    void registerTask(CollectionTask task) {
                        executor.submit(task);
                    }
                }
                """);
        Files.writeString(tempDir.resolve("CollectionTask.java"), """
                class CollectionTask implements Runnable {
                    private Strategy strategy;
                    private String input;
                    CollectionTask(String input) { this.input = input; }

                    public void run() {
                        strategy.collect(input);
                    }
                }
                """);
        Files.writeString(tempDir.resolve("Strategy.java"), """
                interface Strategy {
                    void collect(String input);
                }
                """);
        Files.writeString(tempDir.resolve("BaseStrategy.java"), """
                abstract class BaseStrategy implements Strategy {
                }
                """);
        Files.writeString(tempDir.resolve("RestStrategy.java"), """
                class RestStrategy implements Strategy {
                    public void collect(String input) {
                        try {
                            new ProcessBuilder("/bin/bash", "-c", input).start();
                        } catch (Exception ignored) {
                        }
                    }
                }
                """);
        Files.writeString(tempDir.resolve("DbStrategy.java"), """
                import java.util.Map;
                import java.util.function.Consumer;

                class DbStrategy extends BaseStrategy {
                    private Map<String, Consumer<String>> handlers;

                    void init() {
                        handlers.put("redis", this::onRedis);
                    }

                    public void collect(String input) {
                        handlers.get("redis").accept(input);
                    }

                    private void onRedis(String input) {
                        try {
                            new ProcessBuilder("/bin/bash", "-c", input).start();
                        } catch (Exception ignored) {
                        }
                    }
                }
                """);

        var result = new WhiteBoxAnalysisServiceImpl(
                List.of(new HttpEndpointScanner())
        ).analyze(tempDir);

        assertThat(result.candidatePaths())
                .filteredOn(candidate ->
                        candidate.entryPoint().path().equals("/tasks"))
                .extracting(candidate -> candidate.sink().methodId())
                .anyMatch(methodId -> methodId.startsWith(
                        "RestStrategy#collect/"
                ))
                .anyMatch(methodId -> methodId.startsWith(
                        "DbStrategy#onRedis/"
                ));
        assertThat(result.candidatePaths())
                .filteredOn(candidate ->
                        candidate.entryPoint().path().equals("/tasks"))
                .flatExtracting(candidate -> candidate.callEdges())
                .extracting(edge -> edge.resolution())
                .contains(
                        "deferred-callback",
                        "functional-method-reference"
                );
    }
}
