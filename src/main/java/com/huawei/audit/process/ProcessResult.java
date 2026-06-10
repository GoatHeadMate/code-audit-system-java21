package com.huawei.audit.process;

import java.util.List;

public record ProcessResult(int exitCode, List<String> output) {
    public String joinedOutput() {
        return String.join(System.lineSeparator(), output);
    }
}
