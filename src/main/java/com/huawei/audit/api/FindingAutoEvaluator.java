package com.huawei.audit.api;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class FindingAutoEvaluator {
    static final String REVIEWER = "auto-evaluator";

    public List<Evaluation> evaluate(List<Map<String, Object>> findings) {
        List<Evaluation> evaluations = new ArrayList<>();
        for (int index = 0; index < findings.size(); index++) {
            evaluations.add(evaluate(index, findings.get(index)));
        }
        return List.copyOf(evaluations);
    }

    Evaluation evaluate(int index, Map<String, Object> finding) {
        String existingVerdict = normalize(finding.get("verdict"));
        String severity = normalize(finding.get("severity"));
        String confidence = normalize(finding.get("confidence"));
        String vulnType = normalize(finding.get("vuln_type"));
        String pocStatus = normalize(firstPresent(
                finding.get("poc_status"),
                finding.get("poc_result"),
                finding.get("poc_verdict")
        ));

        if (isSuccess(pocStatus)) {
            return new Evaluation(
                    index,
                    "POC_SUCCESS",
                    "自动评价：finding 已包含 PoC 成功信号，按最高质量反馈记录。",
                    "SUCCESS",
                    "",
                    "PoC 成功是最高信号；后续同类规则可优先验证。",
                    true
            );
        }
        if (isFailure(pocStatus)) {
            return new Evaluation(
                    index,
                    "POC_FAILURE",
                    "自动评价：finding 已包含 PoC 失败信号，记录为需要复核的负向验证。",
                    "FAILURE",
                    "",
                    "PoC 失败不直接抑制漏洞，只作为复核先验。",
                    true
            );
        }
        if ("FALSE_POSITIVE".equals(existingVerdict)) {
            return review(index, "自动评价：上游判定已是误报，保守记录为待复核，避免自动扩散抑制。");
        }
        if (isBlank(confidence) || "LOW".equals(confidence)) {
            return review(index, "自动评价：置信度不足，需要人工复核当前源码证据。");
        }
        if (isAttackChain(vulnType) && listSize(finding.get("data_flow_path")) < 2) {
            return review(index, "自动评价：攻击链缺少完整链路步骤，需要人工复核链路是否真实可达。");
        }
        if (!hasEvidence(finding) && !"HIGH".equals(confidence)) {
            return review(index, "自动评价：证据字段不足且不是高置信，先标记待复核。");
        }
        if ("LOW".equals(severity)) {
            return new Evaluation(
                    index,
                    "RISK_DOWNGRADE",
                    "自动评价：低风险 finding 保守记录为风险降级，可由人工改判。",
                    "",
                    "LOW",
                    "低风险结果进入记忆，但不作为强确认规则。",
                    true
            );
        }
        if ("CONFIRM".equals(existingVerdict) || "HIGH".equals(confidence)) {
            return new Evaluation(
                    index,
                    "CONFIRM",
                    "自动评价：当前 finding 已具备确认判定、高/中置信和可审计证据，记录为确认漏洞。",
                    "",
                    "",
                    "自动确认只作为结构化反馈；后续审计仍需基于当前源码复验。",
                    true
            );
        }
        return review(index, "自动评价：未满足自动确认条件，保守标记待复核。");
    }

    private Evaluation review(int index, String rationale) {
        return new Evaluation(
                index,
                "NEEDS_REVIEW",
                rationale,
                "",
                "",
                "该类结果召回时只能作为注意力先验，不能直接确认或抑制。",
                true
        );
    }

    private boolean hasEvidence(Map<String, Object> finding) {
        return hasText(finding.get("evidence"))
                || hasText(finding.get("message"))
                || hasText(finding.get("entrypoint"))
                || listSize(finding.get("data_flow_path")) > 0;
    }

    private boolean isAttackChain(String vulnType) {
        return vulnType.contains("CHAIN");
    }

    private int listSize(Object value) {
        if (value instanceof List<?> list) {
            return list.size();
        }
        return 0;
    }

    private boolean hasText(Object value) {
        return value != null && !value.toString().isBlank();
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private boolean isSuccess(String value) {
        return switch (value) {
            case "SUCCESS", "PASSED", "POC_SUCCESS", "EXPLOIT_SUCCESS" -> true;
            default -> false;
        };
    }

    private boolean isFailure(String value) {
        return switch (value) {
            case "FAILURE", "FAILED", "POC_FAILURE", "EXPLOIT_FAILED" -> true;
            default -> false;
        };
    }

    private Object firstPresent(Object... values) {
        for (Object value : values) {
            if (value != null && !value.toString().isBlank()) {
                return value;
            }
        }
        return "";
    }

    private String normalize(Object value) {
        if (value == null) {
            return "";
        }
        return value.toString()
                .strip()
                .toUpperCase(Locale.ROOT)
                .replace('-', '_');
    }

    public record Evaluation(
            int findingIndex,
            String verdict,
            String rationale,
            String pocStatus,
            String targetSeverity,
            String learningNote,
            boolean recorded
    ) {
    }
}
