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

    @Test
    void constrainsDynamicLoadingToSupportedReceiverTypes() {
        assertCategory(
                "forName",
                "Class.forName",
                "Class",
                "DYNAMIC_LOADING"
        );
        assertCategory(
                "loadClass",
                "loader.loadClass",
                "URLClassLoader",
                "DYNAMIC_LOADING"
        );
        assertCategory(
                "defineClass",
                "lookup.defineClass",
                "MethodHandles.Lookup",
                "DYNAMIC_LOADING"
        );

        assertThat(classifier.classify(
                "forName",
                "Charset.forName",
                "Charset"
        )).isNull();
        assertThat(classifier.classify(
                "forName",
                "factory.forName",
                "SomeFactory"
        )).isNull();
        assertThat(classifier.classify(
                "forName",
                "factory.forName",
                "ClassNameFactory"
        )).isNull();
    }

    @Test
    void recognizesCommandExecutionWrappers() {
        assertCategory(
                "exec",
                "Runtime.getRuntime().exec(cmd)",
                "Runtime",
                "COMMAND_EXECUTION"
        );
        assertCategory(
                "executeAndGetReturnMsg",
                "RuntimeExec.executeAndGetReturnMsg(commands)",
                "RuntimeExec",
                "COMMAND_EXECUTION"
        );
        assertCategory(
                "exec",
                "RuntimeExec.exec(command)",
                "RuntimeExec",
                "COMMAND_EXECUTION"
        );
    }

    @Test
    void recognizesWebAndDataSinkApis() {
        assertCategory(
                "executeQuery",
                "statement.executeQuery",
                "Statement",
                "SQL_EXECUTION"
        );
        assertCategory(
                "write",
                "writer.write",
                "PrintWriter",
                "HTTP_RESPONSE_WRITE"
        );
        assertCategory(
                "parse",
                "documentBuilder.parse",
                "DocumentBuilder",
                "XML_PARSE"
        );
        assertCategory(
                "setHeader",
                "response.setHeader",
                "HttpServletResponse",
                "HTTP_HEADER_WRITE"
        );
        assertCategory(
                "sendRedirect",
                "response.sendRedirect",
                "HttpServletResponse",
                "HTTP_REDIRECT"
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
