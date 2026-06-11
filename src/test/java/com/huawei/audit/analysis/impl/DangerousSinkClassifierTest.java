package com.huawei.audit.analysis.impl;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class DangerousSinkClassifierTest {
    private final DangerousSinkClassifier classifier =
            new DangerousSinkClassifier();

    @Test
    void recognizesExpressionExecutionApis() {
        assertCategory(
                "executeExpression",
                "MVEL.executeExpression",
                "MVEL",
                "SCRIPT_OR_EXPRESSION_EXECUTION"
        );
        assertCategory(
                "evaluate",
                "groovyShell.evaluate",
                "GroovyShell",
                "SCRIPT_OR_EXPRESSION_EXECUTION"
        );
        assertCategory(
                "process",
                "template.process",
                "Template",
                "SCRIPT_OR_EXPRESSION_EXECUTION"
        );
        assertCategory(
                "evaluate",
                "velocityEngine.evaluate",
                "VelocityEngine",
                "SCRIPT_OR_EXPRESSION_EXECUTION"
        );
        assertCategory(
                "getValue",
                "ognlExpression.getValue",
                "OgnlExpression",
                "SCRIPT_OR_EXPRESSION_EXECUTION"
        );
    }

    @Test
    void recognizesDeserializerAndReflectionApis() {
        assertCategory(
                "load",
                "yaml.load",
                "Yaml",
                "NATIVE_DESERIALIZATION"
        );
        assertCategory(
                "loadAll",
                "snakeYaml.loadAll",
                "Yaml",
                "NATIVE_DESERIALIZATION"
        );
        assertCategory(
                "parseObject",
                "JSON.parseObject",
                "JSON",
                "NATIVE_DESERIALIZATION"
        );
        assertCategory(
                "parse",
                "fastJson.parse",
                "FastJson",
                "NATIVE_DESERIALIZATION"
        );
        assertCategory(
                "invoke",
                "method.invoke",
                "Method",
                "DYNAMIC_LOADING"
        );
    }

    private void assertCategory(
            String method,
            String expression,
            String receiverType,
            String expected
    ) {
        assertThat(classifier.classify(method, expression, receiverType))
                .isNotNull()
                .extracting(DangerousSinkClassifier.SinkMatch::category)
                .isEqualTo(expected);
    }
}
