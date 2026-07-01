package com.huawei.audit.domain;

public enum JobStatus {
    PENDING("pending"),
    CLONING("cloning"),
    RUNNING("running"),
    PARTIAL("partial"),
    DONE("done"),
    FAILED("failed");

    private final String value;

    JobStatus(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
