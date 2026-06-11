package com.huawei.audit.source;

import com.huawei.audit.source.HttpEndpointScanner.SourceHint;
import java.util.List;
import java.util.regex.Pattern;

final class SourceHintScanner {
    private static final List<HintRule> RULES = List.of(
            new HintRule("COMMAND_EXECUTION", Pattern.compile(
                    "\\bProcessBuilder\\b|Runtime\\s*\\.\\s*getRuntime\\s*\\(\\)\\s*\\.\\s*exec\\s*\\("
            )),
            new HintRule("SCRIPT_EXECUTION", Pattern.compile(
                    "\\bScriptEngine\\b|\\.eval\\s*\\(|SpelExpressionParser|parseExpression\\s*\\("
            )),
            new HintRule("NATIVE_DESERIALIZATION", Pattern.compile(
                    "\\bObjectInputStream\\b|\\.readObject\\s*\\(|\\bXMLDecoder\\b|\\.fromXML\\s*\\("
            )),
            new HintRule("DYNAMIC_LOADING", Pattern.compile(
                    "\\bURLClassLoader\\b|Class\\s*\\.\\s*forName\\s*\\(|\\.loadClass\\s*\\(|\\.invoke\\s*\\("
            )),
            new HintRule("JNDI_LOOKUP", Pattern.compile(
                    "\\bInitialContext\\b|\\.lookup\\s*\\("
            )),
            new HintRule("NATIVE_LIBRARY", Pattern.compile(
                    "System\\s*\\.\\s*load(?:Library)?\\s*\\("
            ))
    );

    void scan(
            String relativePath,
            int line,
            String sourceLine,
            List<SourceHint> hints
    ) {
        String stripped = sourceLine.strip();
        if (stripped.isBlank() || stripped.startsWith("//")) {
            return;
        }
        for (HintRule rule : RULES) {
            if (rule.pattern().matcher(stripped).find()) {
                hints.add(new SourceHint(
                        rule.category(),
                        relativePath,
                        line,
                        stripped.length() > 500
                                ? stripped.substring(0, 500)
                                : stripped
                ));
            }
        }
    }

    private record HintRule(String category, Pattern pattern) { }
}
