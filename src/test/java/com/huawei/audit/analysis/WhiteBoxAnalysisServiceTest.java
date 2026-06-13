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
        ).analyze(tempDir, List.of(), null, "claude");

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
        )).analyze(tempDir, List.of(), null, "claude");

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
        ).analyze(tempDir, List.of(), null, "claude");

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
        ).analyze(tempDir, List.of(), null, "claude");

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

    @Test
    void buildsCandidatesForWebAndDataVulnerabilityHunters()
            throws Exception {
        Files.writeString(tempDir.resolve("WebController.java"), """
                import java.io.PrintWriter;
                import java.sql.Statement;
                import javax.servlet.http.HttpServletResponse;
                import javax.xml.parsers.DocumentBuilder;
                import org.springframework.web.bind.annotation.*;

                @RestController
                class WebController {
                    private Statement statement;
                    private DocumentBuilder documentBuilder;

                    @GetMapping("/probe")
                    void probe(
                            @RequestParam String input,
                            HttpServletResponse response
                    ) throws Exception {
                        statement.executeQuery(input);
                        documentBuilder.parse(input);
                        PrintWriter writer = response.getWriter();
                        writer.write(input);
                        response.setHeader("X-Test", input);
                        response.sendRedirect(input);
                    }
                }
                """);

        var result = new WhiteBoxAnalysisServiceImpl(
                List.of(new HttpEndpointScanner())
        ).analyze(tempDir, List.of(), null, "claude");

        assertThat(result.candidatePaths())
                .extracting(candidate -> candidate.sink().category())
                .contains(
                        "SQL_EXECUTION",
                        "HTTP_RESPONSE_WRITE",
                        "XML_PARSE",
                        "HTTP_HEADER_WRITE",
                        "HTTP_REDIRECT"
                );
    }

    @Test
    void discoversCustomActuatorOperationAsEntrypointAndSink()
            throws Exception {
        Files.writeString(tempDir.resolve("AdminEndpoint.java"), """
                import org.springframework.boot.actuate.endpoint.annotation.*;

                @Endpoint(id = "admin")
                class AdminEndpoint {
                    @WriteOperation
                    String execute(String command) {
                        return command;
                    }
                }
                """);

        var result = new WhiteBoxAnalysisServiceImpl(
                List.of(new HttpEndpointScanner())
        ).analyze(tempDir, List.of(), null, "claude");

        assertThat(result.candidatePaths())
                .singleElement()
                .satisfies(candidate -> {
                    assertThat(candidate.entryPoint().path())
                            .isEqualTo("/actuator/admin");
                    assertThat(candidate.entryPoint().httpMethods())
                            .containsExactly("POST");
                    assertThat(candidate.sink().category())
                            .isEqualTo("ACTUATOR_ENDPOINT");
                });
    }

    @Test
    void detectsTaintPropagationThroughStringFormatToProcessBuilder()
            throws Exception {
        Files.writeString(tempDir.resolve("TaskController.java"), """
                import org.springframework.web.bind.annotation.*;

                @RestController
                class TaskController {
                    private TaskExecutor executor;

                    @PostMapping("/task")
                    void execute(@RequestBody String input) {
                        executor.run(input);
                    }
                }
                """);
        Files.writeString(tempDir.resolve("TaskExecutor.java"), """
                class TaskExecutor {
                    void run(String userInput) {
                        String cmd = String.format("bash -c %s", userInput);
                        new ProcessBuilder("/bin/bash", "-c", cmd).start();
                    }
                }
                """);

        var result = new WhiteBoxAnalysisServiceImpl(
                List.of(new HttpEndpointScanner())
        ).analyze(tempDir, List.of(), null, "claude");

        assertThat(result.candidatePaths())
                .filteredOn(c -> c.sink().category().equals("COMMAND_EXECUTION"))
                .isNotEmpty();
    }

    @Test
    void detectsTemplateSubstitutionCommandInjectionThroughAsyncExecution()
            throws Exception {
        Files.writeString(tempDir.resolve("CollectionController.java"), """
                import org.springframework.web.bind.annotation.*;
                import java.util.Map;

                @RestController
                class CollectionController {
                    private TaskCreator creator;

                    @PostMapping("/task")
                    void createTask(@RequestBody TaskRequest request) {
                        creator.createMainTask(request);
                    }
                }
                """);

        Files.writeString(tempDir.resolve("TaskCreator.java"), """
                import java.util.concurrent.ExecutorService;

                class TaskCreator {
                    private ExecutorService pool;

                    void createMainTask(TaskRequest request) {
                        TaskExecutor executor = new TaskExecutor(
                                request.getExtensionParams()
                        );
                        pool.submit(executor);
                    }
                }
                """);

        Files.writeString(tempDir.resolve("TaskExecutor.java"), """
                import java.util.Map;

                class TaskExecutor implements Runnable {
                    private Map<String, String> extensionParams;

                    TaskExecutor(Map<String, String> extensionParams) {
                        this.extensionParams = extensionParams;
                    }

                    public void run() {
                        executeCollection();
                    }

                    private void executeCollection() {
                        CollectorStrategy strategy = new RestCollectorStrategy();
                        strategy.collect(extensionParams);
                    }
                }
                """);

        Files.writeString(tempDir.resolve("CollectorStrategy.java"), """
                import java.util.Map;

                interface CollectorStrategy {
                    void collect(Map<String, String> params);
                }
                """);

        Files.writeString(tempDir.resolve("RestCollectorStrategy.java"), """
                import java.util.Map;

                class RestCollectorStrategy implements CollectorStrategy {
                    public void collect(Map<String, String> params) {
                        String query = "hgetAll DeviceRecord:${dn}";
                        String replaced = QueryUtil.generateQuery(query, params);
                        executeCommand(replaced);
                    }

                    private void executeCommand(String command) {
                        try {
                            String cmd = "source /opt/profile.sh && tool --query \\"" + command + "\\"";
                            new ProcessBuilder("/bin/bash", "-c", cmd).start();
                        } catch (Exception ignored) {}
                    }
                }
                """);

        Files.writeString(tempDir.resolve("QueryUtil.java"), """
                import java.util.Map;

                class QueryUtil {
                    static String generateQuery(String template, Map<String, String> params) {
                        String result = template;
                        for (Map.Entry<String, String> entry : params.entrySet()) {
                            result = result.replace("${" + entry.getKey() + "}", entry.getValue());
                        }
                        return result;
                    }
                }
                """);

        Files.writeString(tempDir.resolve("TaskRequest.java"), """
                import java.util.Map;

                class TaskRequest {
                    Map<String, String> extensionParams;
                    Map<String, String> getExtensionParams() { return extensionParams; }
                }
                """);

        var result = new WhiteBoxAnalysisServiceImpl(
                List.of(new HttpEndpointScanner())
        ).analyze(tempDir, List.of(), null, "claude");

        assertThat(result.candidatePaths())
                .filteredOn(c -> c.entryPoint().path().equals("/task"))
                .filteredOn(c -> c.sink().category().equals("COMMAND_EXECUTION"))
                .isNotEmpty()
                .anySatisfy(candidate -> {
                    assertThat(candidate.methodPath())
                            .extracting(step -> step.className())
                            .contains("CollectionController", "RestCollectorStrategy");
                    assertThat(candidate.taintConfidence())
                            .isIn("CONFIRMED", "LIKELY");
                });

        assertThat(result.taintSummaries())
                .anySatisfy((methodId, summary) -> {
                    if (methodId.contains("RestCollectorStrategy#collect")) {
                        assertThat(summary.hasTaintPropagation()).isTrue();
                    }
                });
    }

    @Test
    void buildsCandidatePathThroughDoubleDelegateChainToRuntimeExecSink()
            throws Exception {
        Files.writeString(tempDir.resolve("HealthService.java"), """
                import javax.ws.rs.*;

                @Path("/check")
                class HealthService {
                    private HealthDelegate delegate;

                    @GET @Path("/data")
                    String checkData(String checkName) {
                        return delegate.checkData(checkName);
                    }
                }
                """);
        Files.writeString(tempDir.resolve("HealthDelegate.java"), """
                interface HealthDelegate {
                    String checkData(String checkName);
                }
                """);
        Files.writeString(tempDir.resolve("HealthDelegateImpl.java"), """
                class HealthDelegateImpl implements HealthDelegate {
                    private TaskChecker taskChecker;

                    public String checkData(String checkName) {
                        return taskChecker.check(checkName);
                    }
                }
                """);
        Files.writeString(tempDir.resolve("TaskChecker.java"), """
                interface TaskChecker {
                    String check(String name);
                }
                """);
        Files.writeString(tempDir.resolve("TaskCheckerImpl.java"), """
                class TaskCheckerImpl implements TaskChecker {
                    public String check(String name) {
                        return doCheck(name);
                    }

                    private String doCheck(String name) {
                        return RuntimeExec.executeAndGetReturnMsg(
                                ("/bin/bash /opt/script.sh " + name).split(" "));
                    }
                }
                """);
        Files.writeString(tempDir.resolve("RuntimeExec.java"), """
                class RuntimeExec {
                    static String executeAndGetReturnMsg(String[] commands) {
                        try {
                            Process p = Runtime.getRuntime().exec(commands);
                            return new String(p.getInputStream().readAllBytes());
                        } catch (Exception e) { return ""; }
                    }
                }
                """);

        var result = new WhiteBoxAnalysisServiceImpl(
                List.of(new HttpEndpointScanner())
        ).analyze(tempDir, List.of(), null, "claude");

        assertThat(result.candidatePaths())
                .as("double delegate chain should reach RuntimeExec sink")
                .filteredOn(c -> c.sink().category().equals("COMMAND_EXECUTION"))
                .isNotEmpty()
                .anySatisfy(candidate -> {
                    assertThat(candidate.entryPoint().path())
                            .isEqualTo("/check/data");
                    assertThat(candidate.methodPath())
                            .extracting(step -> step.className())
                            .contains("HealthService", "HealthDelegateImpl",
                                    "TaskCheckerImpl");
                });
    }

    @Test
    void detectsArgumentInjectionThroughSplitAndWrapperExec() throws Exception {
        Files.writeString(tempDir.resolve("TaskCheckService.java"), """
                package com.example;
                import javax.ws.rs.*;

                @Path("/dpfault/task/v1")
                public class TaskCheckService {
                    @GET @Path("/check/{type}")
                    public String check(@QueryParam("checkName") String checkName) {
                        String ip = "10.0.0.1";
                        getOpenGeminiTag(ip, checkName);
                        return "ok";
                    }

                    private String getOpenGeminiTag(String ip, String checkName) {
                        String cmd = "/bin/bash /opt/script.sh " + ip + " " + checkName;
                        return RuntimeExec.executeAndGetReturnMsg(cmd.split(" "));
                    }
                }
                """);
        Files.writeString(tempDir.resolve("RuntimeExec.java"), """
                package com.example;

                public class RuntimeExec {
                    public static String executeAndGetReturnMsg(String[] commands) {
                        try {
                            Process p = Runtime.getRuntime().exec(commands);
                            return new String(p.getInputStream().readAllBytes());
                        } catch (Exception e) { return ""; }
                    }
                }
                """);

        var result = new WhiteBoxAnalysisServiceImpl(
                List.of(new HttpEndpointScanner())
        ).analyze(tempDir, List.of(), null, "claude");

        assertThat(result.candidatePaths())
                .as("should find path through split() + wrapper exec to Runtime.exec sink")
                .isNotEmpty();
        assertThat(result.candidatePaths())
                .anyMatch(path ->
                        path.sink().category().equals("COMMAND_EXECUTION")
                                && path.entryPoint().path().contains("/check"));
    }
}
