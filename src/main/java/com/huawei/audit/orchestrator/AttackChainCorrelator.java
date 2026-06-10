package com.huawei.audit.orchestrator;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class AttackChainCorrelator {
    private static final Map<String, Integer> SEVERITY = Map.of(
            "CRITICAL", 4, "HIGH", 3, "MEDIUM", 2, "LOW", 1
    );

    private static final List<ChainRule> RULES = List.of(
            new ChainRule("chain-ssrf-cmdinj", "SSRF -> Command Injection -> RCE",
                    Set.of("SSRF"), Set.of("COMMAND_INJECTION"), "CRITICAL", 0.80,
                    "SSRF may reach an internal command injection endpoint and form an RCE chain."),
            new ChainRule("chain-ssrf-deser", "SSRF -> Deserialization -> RCE",
                    Set.of("SSRF"), Set.of("DESERIALIZATION"), "CRITICAL", 0.80,
                    "SSRF may deliver malicious serialized data to an internal endpoint."),
            new ChainRule("chain-ssrf-xxe", "SSRF -> XXE",
                    Set.of("SSRF"), Set.of("XXE"), "HIGH", 0.70,
                    "SSRF may reach an internal XML parser and trigger XXE."),
            new ChainRule("chain-noauth-cmdinj", "Missing Auth + Command Injection",
                    Set.of("MISSING_AUTH"), Set.of("COMMAND_INJECTION"), "CRITICAL", 0.85,
                    "An unauthenticated caller may reach command injection."),
            new ChainRule("chain-noauth-deser", "Missing Auth + Deserialization",
                    Set.of("MISSING_AUTH"), Set.of("DESERIALIZATION"), "CRITICAL", 0.85,
                    "An unauthenticated caller may reach unsafe deserialization."),
            new ChainRule("chain-noauth-ssrf", "Missing Auth + SSRF",
                    Set.of("MISSING_AUTH"), Set.of("SSRF"), "HIGH", 0.80,
                    "An unauthenticated caller may use the SSRF endpoint."),
            new ChainRule("chain-weak-whitelist-ssrf", "Weak Whitelist -> SSRF Bypass",
                    Set.of("WEAK_WHITELIST"), Set.of("SSRF"), "HIGH", 0.80,
                    "Substring whitelist validation may be bypassed to exploit SSRF."),
            new ChainRule("chain-ssti-cmdinj", "Template Injection -> Command Execution",
                    Set.of("SSTI"), Set.of("COMMAND_INJECTION"), "CRITICAL", 0.75,
                    "Template injection and command execution may combine into RCE.")
    );

    public List<Map<String, Object>> correlate(
            List<Map<String, Object>> findings,
            String appPackage
    ) {
        Map<String, List<Map<String, Object>>> byType = new LinkedHashMap<>();
        for (Map<String, Object> finding : findings) {
            byType.computeIfAbsent(upperText(finding, "vuln_type"), ignored -> new ArrayList<>())
                    .add(finding);
        }

        List<Map<String, Object>> chains = new ArrayList<>();
        for (ChainRule rule : RULES) {
            List<Map<String, Object>> amplifiers = collect(byType, rule.amplifiers());
            List<Map<String, Object>> targets = collect(byType, rule.targets());
            if (amplifiers.isEmpty() || targets.isEmpty()) {
                continue;
            }

            Map<String, Object> amplifier = best(amplifiers);
            Map<String, Object> target = best(targets);
            boolean amplifierInApp = inAppPackage(amplifier, appPackage);
            boolean targetInApp = inAppPackage(target, appPackage);
            boolean needsReview = !appPackage.isBlank() && !amplifierInApp && !targetInApp;
            double confidence = rule.confidence();
            if (needsReview) {
                if (confidence(amplifier) < 0.85 || confidence(target) < 0.85) {
                    continue;
                }
                confidence = Math.round(confidence * 0.7 * 100.0) / 100.0;
            }
            if (confidence < 0.60) {
                continue;
            }

            Map<String, Object> chain = new LinkedHashMap<>();
            chain.put("rule_id", rule.id());
            chain.put("title", rule.name());
            chain.put("severity", rule.severity());
            chain.put("confidence", confidence);
            chain.put("file_path", amplifier.getOrDefault("file_path", ""));
            chain.put("start_line", amplifier.getOrDefault("start_line", 0));
            chain.put("message", rule.message()
                    + (needsReview ? " Reachability from application code requires review." : ""));
            chain.put("discovered_by", "chain-correlator");
            chain.put("vuln_type", "ATTACK_CHAIN");
            chain.put("vulnerability_type", "ATTACK_CHAIN");
            chain.put("chain_name", rule.name());
            chain.put("needs_reachability_review", needsReview);
            chain.put("data_flow_path", List.of(
                    chainStep("amplifier", amplifier, amplifierInApp),
                    chainStep("target", target, targetInApp)
            ));
            chain.put("chain_components", Map.of(
                    "amplifier", amplifier,
                    "target", target,
                    "amplifier_count", amplifiers.size(),
                    "target_count", targets.size()
            ));
            chains.add(chain);
        }

        chains.sort(Comparator
                .comparingInt((Map<String, Object> finding) ->
                        SEVERITY.getOrDefault(upperText(finding, "severity"), 0))
                .thenComparingDouble(this::confidence)
                .reversed());
        return chains;
    }

    private List<Map<String, Object>> collect(
            Map<String, List<Map<String, Object>>> byType,
            Set<String> types
    ) {
        return types.stream()
                .flatMap(type -> byType.getOrDefault(type, List.of()).stream())
                .toList();
    }

    private Map<String, Object> best(List<Map<String, Object>> findings) {
        return findings.stream().max(Comparator.comparingDouble(this::confidence)).orElseThrow();
    }

    private Map<String, Object> chainStep(
            String step,
            Map<String, Object> finding,
            boolean inAppPackage
    ) {
        return Map.of(
                "step", step,
                "file", finding.getOrDefault("file_path", ""),
                "line", finding.getOrDefault("start_line", 0),
                "type", finding.getOrDefault("vuln_type", ""),
                "in_app_package", inAppPackage
        );
    }

    private boolean inAppPackage(Map<String, Object> finding, String appPackage) {
        if (appPackage == null || appPackage.isBlank()) {
            return true;
        }
        String file = rawText(finding, "file_path").replace('\\', '/');
        return file.contains(appPackage.replace('.', '/'));
    }

    private double confidence(Map<String, Object> finding) {
        Object value = finding.get("confidence");
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        try {
            return value == null ? 0.0 : Double.parseDouble(value.toString());
        } catch (NumberFormatException ignored) {
            return 0.0;
        }
    }

    private String upperText(Map<String, Object> finding, String key) {
        return rawText(finding, key).toUpperCase(Locale.ROOT);
    }

    private String rawText(Map<String, Object> finding, String key) {
        Object value = finding.get(key);
        return value == null ? "" : value.toString();
    }

    private record ChainRule(
            String id,
            String name,
            Set<String> amplifiers,
            Set<String> targets,
            String severity,
            double confidence,
            String message
    ) { }
}
