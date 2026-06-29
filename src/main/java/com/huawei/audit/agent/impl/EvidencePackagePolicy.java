package com.huawei.audit.agent.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CandidatePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Coverage;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.EntryPoint;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StoredCandidate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

final class EvidencePackagePolicy {
    private static final Map<String, Set<String>> HUNTER_SINKS = Map.ofEntries(
            Map.entry("code_execution", Set.of(
                    "COMMAND_EXECUTION",
                    "SCRIPT_OR_EXPRESSION_EXECUTION",
                    "NATIVE_LIBRARY"
            )),
            Map.entry("sql_injection", Set.of(
                    "SQL_EXECUTION"
            )),
            Map.entry("ssrf", Set.of(
                    "OUTBOUND_HTTP"
            )),
            Map.entry("authorization", Set.of(
                    "SERVLET_ENTRY",
                    "FILTER_ENTRY"
            )),
            Map.entry("unsafe_parsing", Set.of(
                    "NATIVE_DESERIALIZATION",
                    "DYNAMIC_LOADING",
                    "XML_PARSE"
            )),
            Map.entry("http_output", Set.of(
                    "HTTP_RESPONSE_WRITE",
                    "HTTP_HEADER_WRITE",
                    "HTTP_REDIRECT"
            )),
            Map.entry("file_operations", Set.of(
                    "FILE_WRITE"
            )),
            Map.entry("component_vulns", Set.of(
                    "ACTUATOR_ENDPOINT",
                    "JNDI_LOOKUP"
            ))
    );

    private EvidencePackagePolicy() {
    }

    static Set<String> sinkCategories(String hunter) {
        return HUNTER_SINKS.getOrDefault(baseHunterName(hunter), Set.of());
    }

    static List<CandidatePath> relevantCandidates(
            String hunter,
            List<CandidatePath> candidates
    ) {
        Set<String> categories = HUNTER_SINKS.get(baseHunterName(hunter));
        if (categories == null) {
            return List.of();
        }
        return candidates.stream()
                .filter(candidate ->
                        categories.contains(candidate.sink().category()))
                .sorted(candidatePriority())
                .toList();
    }

    static List<StoredCandidate> relevantStoredCandidates(
            String hunter,
            List<StoredCandidate> candidates
    ) {
        Set<String> categories = HUNTER_SINKS.get(baseHunterName(hunter));
        if (categories == null) {
            return List.of();
        }
        return candidates.stream()
                .filter(candidate -> categories.contains(
                        candidate.executionPath().sink().category()
                ))
                .sorted(Comparator.comparing(
                        (StoredCandidate c) -> confidenceRank(
                                c.correlationConfidence()
                        )
                ).thenComparingInt(
                        c -> c.executionPath().callDepth()
                ))
                .toList();
    }

    static List<Map<String, Object>> authorizationSurface(
            List<EntryPoint> entryPoints,
            List<CandidatePath> candidates
    ) {
        Map<String, List<CandidatePath>> candidatesByEntry = candidates.stream()
                .filter(candidate -> candidate.entryPoint() != null)
                .collect(Collectors.groupingBy(
                        candidate -> candidate.entryPoint().id()
                ));
        List<Map<String, Object>> result = new ArrayList<>();
        for (EntryPoint entryPoint : entryPoints) {
            if (!isAuthorizationProtocol(entryPoint.protocol())) {
                continue;
            }
            List<CandidatePath> reachable = candidatesByEntry.getOrDefault(
                    entryPoint.id(),
                    List.of()
            );
            Map<String, Object> summary = endpointSummary(
                    entryPoint,
                    reachable,
                    "authorization-surface",
                    "authorization"
            );
            result.add(Map.copyOf(summary));
        }
        return List.copyOf(result);
    }

    static List<Map<String, Object>> endpointReviewSurface(
            String hunter,
            List<EntryPoint> entryPoints,
            List<CandidatePath> candidates
    ) {
        String baseHunter = baseHunterName(hunter);
        Set<String> keywords = endpointKeywords(baseHunter);
        Map<String, List<CandidatePath>> candidatesByEntry = candidates.stream()
                .filter(candidate -> candidate.entryPoint() != null)
                .collect(Collectors.groupingBy(
                        candidate -> candidate.entryPoint().id()
                ));
        return entryPoints.stream()
                .filter(entryPoint -> isAuthorizationProtocol(entryPoint.protocol()))
                .filter(entryPoint -> (!keywords.isEmpty()
                        && containsAny(entryPoint, keywords))
                        || !riskHypotheses(entryPoint, baseHunter).isEmpty())
                .map(entryPoint -> endpointSummary(
                        entryPoint,
                        candidatesByEntry.getOrDefault(entryPoint.id(), List.of()),
                        "business-intent-surface",
                        baseHunter
                ))
                .toList();
    }

    static List<EndpointReviewTeam> endpointReviewTeams(
            String hunter,
            List<Map<String, Object>> endpointSurface
    ) {
        String baseHunter = baseHunterName(hunter);
        Map<String, EndpointReviewTeamBuilder> builders = new LinkedHashMap<>();
        for (Map<String, Object> endpoint : endpointSurface) {
            String focus = primaryRisk(endpoint);
            String slug = slug(focus);
            String teamName = baseHunter + "_team_" + slug;
            builders.computeIfAbsent(
                    teamName,
                    ignored -> new EndpointReviewTeamBuilder(teamName, focus)
            ).endpoints().add(endpoint);
        }
        return builders.values().stream()
                .map(builder -> new EndpointReviewTeam(
                        builder.teamName(),
                        builder.focus(),
                        List.copyOf(builder.endpoints())
                ))
                .toList();
    }

    private static Map<String, Object> endpointSummary(
            EntryPoint entryPoint,
            List<CandidatePath> reachable,
            String discoverySource,
            String hunter
    ) {
        List<String> sinkCategories = reachable.stream()
                .map(candidate -> candidate.sink().category())
                .distinct()
                .sorted()
                .toList();
        int minimumCallDepth = reachable.stream()
                .mapToInt(CandidatePath::callDepth)
                .min()
                .orElse(-1);

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("entrypoint_id", entryPoint.id());
        summary.put("protocol", entryPoint.protocol());
        summary.put("http_methods", entryPoint.httpMethods());
        summary.put("path", entryPoint.path());
        summary.put("class_name", entryPoint.className());
        summary.put("method_name", entryPoint.methodName());
        summary.put("file_path", entryPoint.filePath());
        summary.put("start_line", entryPoint.startLine());
        summary.put("framework", entryPoint.framework());
        summary.put("security_annotations", entryPoint.securityAnnotations());
        summary.put("method_security_present",
                !entryPoint.securityAnnotations().isEmpty());
        summary.put("binding_status", entryPoint.bindingStatus());
        summary.put("reachable_sink_categories", sinkCategories);
        summary.put("candidate_path_count", reachable.size());
        summary.put("minimum_call_depth", minimumCallDepth);
        summary.put("discovery_source", discoverySource);
        summary.put("business_intents", businessIntents(entryPoint));
        summary.put("risk_hypotheses", riskHypotheses(entryPoint, hunter));
        summary.put("suggested_poc_checks", suggestedPocChecks(entryPoint, hunter));
        return Map.copyOf(summary);
    }

    private static boolean isAuthorizationProtocol(String protocol) {
        return "HTTP".equalsIgnoreCase(protocol)
                || "WEBSOCKET".equalsIgnoreCase(protocol);
    }

    private static Set<String> endpointKeywords(String hunter) {
        return switch (hunter) {
            case "code_execution" -> Set.of(
                    "rce", "cmd", "command", "exec", "process", "runtime",
                    "spel", "ognl", "qlexpress", "expression", "classloader"
            );
            case "ssrf" -> Set.of(
                    "ssrf", "url", "proxy", "fetch", "httpclient", "okhttp",
                    "urlconnection", "resttemplate", "webclient"
            );
            case "file_operations" -> Set.of(
                    "file", "upload", "download", "path", "traversal",
                    "directory", "zip", "read", "write"
            );
            case "http_output" -> Set.of(
                    "xss", "jsonp", "cors", "redirect", "crlf", "header",
                    "cookie", "response"
            );
            case "unsafe_parsing" -> Set.of(
                    "xxe", "xml", "sax", "dom4j", "jdom", "poi", "xlsx",
                    "deserialize", "deserialization", "unserialize",
                    "fastjson", "xstream", "yaml", "spel", "ssti",
                    "velocity", "qlexpress", "expression", "classloader"
            );
            case "component_vulns" -> Set.of(
                    "log4j", "jndi", "actuator", "druid", "swagger",
                    "shiro", "fastjson", "xstream"
            );
            default -> Set.of();
        };
    }

    static String baseHunterName(String hunter) {
        int batchIdx = hunter.indexOf("_batch_");
        String withoutBatch = batchIdx >= 0 ? hunter.substring(0, batchIdx) : hunter;
        int teamIdx = withoutBatch.indexOf("_team_");
        return teamIdx >= 0 ? withoutBatch.substring(0, teamIdx) : withoutBatch;
    }

    private static List<String> businessIntents(EntryPoint entryPoint) {
        String text = endpointText(entryPoint);
        List<String> intents = new ArrayList<>();
        addIfMatch(intents, text, "FILE_IMPORT_UPLOAD",
                "upload", "import", "multipart", "xlsx", "excel", "xml", "zip");
        addIfMatch(intents, text, "FILE_EXPORT_DOWNLOAD",
                "download", "export", "file", "attachment", "read");
        addIfMatch(intents, text, "SERVER_SIDE_FETCH_CALLBACK",
                "callback", "webhook", "url", "uri", "proxy", "fetch",
                "httpclient", "okhttp", "urlconnection", "resttemplate", "webclient");
        addIfMatch(intents, text, "NAVIGATION_REDIRECT_CALLBACK",
                "redirect", "returnurl", "return_url", "callback", "jsonp");
        addIfMatch(intents, text, "QUERY_CONSTRUCTION",
                "search", "query", "filter", "where", "order", "sort", "sql");
        addIfMatch(intents, text, "REMOTE_OPERATION_EXECUTION",
                "cmd", "command", "exec", "execute", "process", "runtime", "rce");
        addIfMatch(intents, text, "STRUCTURED_DOCUMENT_PARSE",
                "xxe", "xml", "sax", "dom4j", "jdom", "poi", "xlsx", "excel", "yaml");
        addIfMatch(intents, text, "OBJECT_DESERIALIZATION",
                "deserialize", "deserialization", "unserialize", "fastjson", "xstream");
        addIfMatch(intents, text, "EXPRESSION_TEMPLATE_EVAL",
                "spel", "ognl", "qlexpress", "expression", "template",
                "velocity", "ssti");
        addIfMatch(intents, text, "AUTH_SESSION",
                "login", "auth", "token", "jwt", "session", "cookie");
        addIfMatch(intents, text, "AUTHORIZATION_ADMIN",
                "admin", "role", "permission", "privilege", "user");
        addIfMatch(intents, text, "HTTP_RESPONSE_SHAPING",
                "xss", "jsonp", "cors", "header", "cookie", "response", "crlf");
        addIfMatch(intents, text, "COMPONENT_DYNAMIC_LOOKUP",
                "log4j", "jndi", "actuator", "druid", "swagger", "shiro");
        return List.copyOf(intents);
    }

    private static List<Map<String, Object>> riskHypotheses(
            EntryPoint entryPoint,
            String hunter
    ) {
        List<String> intents = businessIntents(entryPoint);
        List<Map<String, Object>> risks = new ArrayList<>();
        if ("file_operations".equals(hunter)
                && containsIntent(intents, "FILE_IMPORT_UPLOAD", "FILE_EXPORT_DOWNLOAD")) {
            risks.add(risk("PATH_TRAVERSAL_OR_ARBITRARY_FILE_ACCESS",
                    "file-oriented business endpoint",
                    "Check whether request-controlled filename/path is canonicalized and confined."));
        }
        if ("unsafe_parsing".equals(hunter)
                && containsIntent(intents, "FILE_IMPORT_UPLOAD", "STRUCTURED_DOCUMENT_PARSE",
                "OBJECT_DESERIALIZATION", "EXPRESSION_TEMPLATE_EVAL")) {
            risks.add(risk("UNSAFE_PARSING_OR_DESERIALIZATION",
                    "parser/import/expression-oriented business endpoint",
                    "Check parser hardening, type allowlists, expression evaluation and safe examples."));
        }
        if ("ssrf".equals(hunter)
                && containsIntent(intents, "SERVER_SIDE_FETCH_CALLBACK")) {
            risks.add(risk("SSRF",
                    "server-side URL/callback/proxy business endpoint",
                    "Check URL source, host/IP allowlist, redirects and internal-network reachability."));
        }
        if ("sql_injection".equals(hunter)
                && containsIntent(intents, "QUERY_CONSTRUCTION")) {
            risks.add(risk("SQL_INJECTION",
                    "query/filter/order business endpoint",
                    "Check string concatenation, MyBatis ${}, dynamic order-by and parameter binding."));
        }
        if ("code_execution".equals(hunter)
                && containsIntent(intents, "REMOTE_OPERATION_EXECUTION",
                "EXPRESSION_TEMPLATE_EVAL")) {
            risks.add(risk("COMMAND_OR_EXPRESSION_EXECUTION",
                    "remote operation/expression business endpoint",
                    "Check command construction, ProcessBuilder arguments and expression allowlists."));
        }
        if ("http_output".equals(hunter)
                && containsIntent(intents, "HTTP_RESPONSE_SHAPING",
                "NAVIGATION_REDIRECT_CALLBACK", "FILE_EXPORT_DOWNLOAD")) {
            risks.add(risk("HTTP_OUTPUT_INJECTION_OR_OPEN_REDIRECT",
                    "response/header/redirect/download business endpoint",
                    "Check reflected output encoding, header CRLF, redirect allowlists and CORS policy."));
        }
        if ("authorization".equals(hunter)
                && containsIntent(intents, "AUTH_SESSION", "AUTHORIZATION_ADMIN",
                "REMOTE_OPERATION_EXECUTION", "FILE_EXPORT_DOWNLOAD", "FILE_IMPORT_UPLOAD")) {
            risks.add(risk("BROKEN_ACCESS_CONTROL",
                    "sensitive business endpoint",
                    "Check method security, global filters, role checks and tenant/resource ownership."));
        }
        if ("component_vulns".equals(hunter)
                && containsIntent(intents, "COMPONENT_DYNAMIC_LOOKUP",
                "OBJECT_DESERIALIZATION")) {
            risks.add(risk("COMPONENT_OR_CONFIGURATION_VULNERABILITY",
                    "component-specific exposed endpoint",
                    "Check dependency/config exposure and known dangerous framework features."));
        }
        return List.copyOf(risks);
    }

    private static List<String> suggestedPocChecks(
            EntryPoint entryPoint,
            String hunter
    ) {
        return riskHypotheses(entryPoint, hunter).stream()
                .map(risk -> risk.get("validation").toString())
                .toList();
    }

    private static Map<String, Object> risk(
            String vulnType,
            String reason,
            String validation
    ) {
        return Map.of(
                "vuln_type", vulnType,
                "reason", reason,
                "validation", validation
        );
    }

    private static String primaryRisk(Map<String, Object> endpoint) {
        Object value = endpoint.get("risk_hypotheses");
        if (value instanceof List<?> risks
                && !risks.isEmpty()
                && risks.get(0) instanceof Map<?, ?> risk) {
            Object vulnType = risk.get("vuln_type");
            if (vulnType != null && !vulnType.toString().isBlank()) {
                return vulnType.toString();
            }
        }
        return "GENERAL_ENDPOINT_REVIEW";
    }

    private static String slug(String value) {
        String slug = value.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "_")
                .replaceAll("^_+|_+$", "");
        return slug.isBlank() ? "general" : slug;
    }

    private static boolean containsIntent(List<String> intents, String... expected) {
        Set<String> intentSet = Set.copyOf(intents);
        for (String item : expected) {
            if (intentSet.contains(item)) {
                return true;
            }
        }
        return false;
    }

    private static void addIfMatch(
            List<String> intents,
            String text,
            String intent,
            String... keywords
    ) {
        for (String keyword : keywords) {
            if (text.contains(keyword)) {
                intents.add(intent);
                return;
            }
        }
    }

    private static boolean containsAny(EntryPoint entryPoint, Set<String> keywords) {
        String haystack = endpointText(entryPoint);
        return keywords.stream().anyMatch(haystack::contains);
    }

    private static String endpointText(EntryPoint entryPoint) {
        return String.join(" ",
                entryPoint.path(),
                entryPoint.className(),
                entryPoint.methodName(),
                entryPoint.filePath()
        ).toLowerCase(Locale.ROOT);
    }

    private static Comparator<CandidatePath> candidatePriority() {
        return Comparator
                .comparing((CandidatePath c) -> confidenceRank(
                        c.staticConfidence()
                ))
                .thenComparingInt(CandidatePath::callDepth);
    }

    private static int confidenceRank(String confidence) {
        return switch (confidence) {
            case "HIGH" -> 0;
            case "MEDIUM" -> 1;
            default -> 2;
        };
    }

    static Map<String, Object> coverageSummary(Coverage coverage) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("java_files", coverage.javaFiles());
        summary.put("parsed_methods", coverage.parsedMethods());
        summary.put("discovered_entrypoints", coverage.discoveredEntryPoints());
        summary.put("bound_entrypoints", coverage.boundEntryPoints());
        summary.put("unresolved_entrypoints", coverage.unresolvedEntryPoints());
        summary.put("dangerous_sinks", coverage.dangerousSinks());
        summary.put("candidate_paths", coverage.candidatePaths());
        summary.put("storage_accesses", coverage.storageAccesses());
        summary.put("stored_candidates", coverage.storedCandidates());
        summary.put(
                "entrypoints_reaching_sink",
                coverage.entryPointsReachingSink()
        );
        summary.put("unresolved_calls", coverage.unresolvedCalls());
        summary.put("parser_diagnostics", coverage.parserDiagnostics());
        summary.put("entry_binding_rate", coverage.entryBindingRate());
        summary.put(
                "entrypoints_by_discoverer",
                coverage.entryPointsByDiscoverer()
        );
        summary.put("sinks_by_category", coverage.sinksByCategory());
        summary.put("candidate_paths_by_sink", coverage.candidatePathsBySink());
        return Map.copyOf(summary);
    }

    record EndpointReviewTeam(
            String teamName,
            String focus,
            List<Map<String, Object>> endpoints
    ) { }

    private record EndpointReviewTeamBuilder(
            String teamName,
            String focus,
            List<Map<String, Object>> endpoints
    ) {
        EndpointReviewTeamBuilder(String teamName, String focus) {
            this(teamName, focus, new ArrayList<>());
        }
    }
}
