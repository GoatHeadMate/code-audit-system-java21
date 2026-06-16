package com.huawei.audit.process;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.springframework.stereotype.Component;

@Component
public class ProcessRunner {
    private final ExecutorService executor;

    public ProcessRunner(ExecutorService executor) {
        this.executor = executor;
    }

    public ProcessResult run(
            List<String> command,
            Path workingDirectory,
            Map<String, String> environment,
            Duration timeout,
            Consumer<String> outputConsumer
    ) throws IOException, InterruptedException {
        return run(command, workingDirectory, environment, timeout,
                null, Charset.defaultCharset(), outputConsumer);
    }

    public ProcessResult run(
            List<String> command,
            Path workingDirectory,
            Map<String, String> environment,
            Duration timeout,
            String standardInput,
            Consumer<String> outputConsumer
    ) throws IOException, InterruptedException {
        return run(command, workingDirectory, environment, timeout,
                standardInput, StandardCharsets.UTF_8, outputConsumer);
    }

    private ProcessResult run(
            List<String> command,
            Path workingDirectory,
            Map<String, String> environment,
            Duration timeout,
            String standardInput,
            Charset outputCharset,
            Consumer<String> outputConsumer
    ) throws IOException, InterruptedException {
        ProcessBuilder builder = new ProcessBuilder(command)
                .directory(workingDirectory.toFile())
                .redirectErrorStream(true);
        builder.environment().putAll(environment);
        Process process = builder.start();

        List<String> output = new ArrayList<>();
        Future<?> reader = executor.submit(() -> {
            try (BufferedReader lines = process.inputReader(outputCharset)) {
                String line;
                while ((line = lines.readLine()) != null) {
                    synchronized (output) {
                        output.add(line);
                    }
                    outputConsumer.accept(line);
                }
            } catch (IOException exception) {
                outputConsumer.accept("[process] output read failed: " + exception.getMessage());
            }
        });

        if (standardInput != null) {
            try (var writer = process.outputWriter(StandardCharsets.UTF_8)) {
                writer.write(standardInput);
            }
        } else {
            process.getOutputStream().close();
        }

        if (timeout != null) {
            boolean completed = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!completed) {
                process.destroy();
                if (!process.waitFor(5, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                }
                throw new IOException("process timed out after " + timeout + ": " + command);
            }
        } else {
            process.waitFor();
        }

        try {
            reader.get(5, TimeUnit.SECONDS);
        } catch (Exception ignored) {
            reader.cancel(true);
        }
        synchronized (output) {
            return new ProcessResult(process.exitValue(), List.copyOf(output));
        }
    }
}
