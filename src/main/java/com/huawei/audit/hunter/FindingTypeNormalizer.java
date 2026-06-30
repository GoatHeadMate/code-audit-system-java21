package com.huawei.audit.hunter;

import java.util.Locale;

final class FindingTypeNormalizer {
    private FindingTypeNormalizer() {
    }

    static String normalize(String rawType, String ruleId, String title, String hunter) {
        String raw = normalizeToken(rawType);
        String rule = normalizeToken(ruleId);
        String text = String.join("_",
                raw,
                rule,
                normalizeToken(title),
                normalizeToken(hunter)
        );

        if (raw.equals("ATTACK_CHAIN") || rule.startsWith("CHAIN_")) {
            return "ATTACK_CHAIN";
        }

        String byRule = normalizeByRule(rule, text);
        if (!byRule.isBlank()) {
            return byRule;
        }

        String byText = normalizeByText(text);
        if (!byText.isBlank()) {
            return byText;
        }

        return raw.isBlank() ? normalizeToken(hunter) : raw;
    }

    private static String normalizeByRule(String rule, String text) {
        if (rule.isBlank()) {
            return "";
        }
        if (rule.startsWith("CSRF_") || rule.equals("CSRF")) {
            return "CSRF";
        }
        if (rule.startsWith("JWT_") || rule.equals("JWT")) {
            return "JWT_WEAKNESS";
        }
        if (rule.startsWith("COOKIE_") || rule.startsWith("SESSION_")) {
            return "COOKIE_SECURITY";
        }
        if (rule.startsWith("AUTHZ_") || rule.startsWith("AUTH_")) {
            if (containsAny(text, "CSRF")) {
                return "CSRF";
            }
            if (containsAny(text, "JWT", "TOKEN", "SECRET")) {
                return "JWT_WEAKNESS";
            }
            if (containsAny(text, "COOKIE", "SESSION", "SAMESITE", "HTTPONLY")) {
                return "COOKIE_SECURITY";
            }
            if (containsAny(text, "IDOR", "TENANT", "OBJECT_REFERENCE")) {
                return "IDOR";
            }
            if (containsAny(text, "BYPASS", "AUTHENTICATION")) {
                return "AUTH_BYPASS";
            }
            return "BROKEN_ACCESS_CONTROL";
        }
        if (rule.startsWith("SQLI_") || rule.startsWith("SQL_")) {
            return "SQL_INJECTION";
        }
        if (rule.startsWith("SSRF_") || rule.equals("SSRF")) {
            return "SSRF";
        }
        if (rule.startsWith("CMDINJ_") || rule.startsWith("COMMAND_")) {
            return "COMMAND_INJECTION";
        }
        if (rule.startsWith("SSTI_") || rule.startsWith("SPEL_")
                || rule.startsWith("MVEL_") || rule.startsWith("OGNL_")) {
            if (containsAny(text, "SPEL", "MVEL", "OGNL", "EXPRESSION")) {
                return "EXPRESSION_INJECTION";
            }
            return "TEMPLATE_INJECTION";
        }
        if (rule.startsWith("SCRIPT_") || rule.startsWith("NASHORN_")
                || rule.startsWith("GROOVY_")) {
            return "SCRIPT_INJECTION";
        }
        if (rule.startsWith("DESER_") || rule.startsWith("FASTJSON_")
                || rule.startsWith("XSTREAM_")) {
            return "DESERIALIZATION";
        }
        if (rule.startsWith("XXE_") || rule.equals("XXE")) {
            return "XXE";
        }
        if (rule.startsWith("XSS_") || rule.equals("XSS")) {
            return "XSS";
        }
        if (rule.startsWith("CRLF_")) {
            return "CRLF_INJECTION";
        }
        if (rule.startsWith("OPEN_REDIRECT_") || rule.startsWith("REDIRECT_")) {
            return "OPEN_REDIRECT";
        }
        if (rule.startsWith("CORS_")) {
            return "CORS_MISCONFIG";
        }
        if (rule.startsWith("JSONP_")) {
            return "JSONP_HIJACK";
        }
        if (rule.startsWith("PATHTRAV_") || rule.startsWith("PATH_TRAVERSAL_")) {
            return "PATH_TRAVERSAL";
        }
        if (rule.startsWith("UPLOAD_") || rule.startsWith("FILE_UPLOAD_")) {
            return "FILE_UPLOAD";
        }
        if (rule.startsWith("ACTUATOR_")) {
            return "ACTUATOR_EXPOSURE";
        }
        if (rule.startsWith("LOG4J_") || rule.startsWith("LOG4SHELL_")) {
            return "LOG4SHELL";
        }
        if (rule.startsWith("H2_") || rule.startsWith("COMPONENT_")
                || rule.startsWith("CVE_")) {
            return "COMPONENT_VULN";
        }
        return "";
    }

    private static String normalizeByText(String text) {
        if (containsAny(text, "BROKEN_ACCESS_CONTROL")) {
            if (containsAny(text, "CSRF")) {
                return "CSRF";
            }
            if (containsAny(text, "JWT", "TOKEN_FORGERY", "WEAK_SECRET")) {
                return "JWT_WEAKNESS";
            }
            if (containsAny(text, "COOKIE", "SESSION")) {
                return "COOKIE_SECURITY";
            }
            return "BROKEN_ACCESS_CONTROL";
        }
        if (containsAny(text, "AUTHENTICATION_BYPASS", "AUTHORIZATION_BYPASS",
                "AUTH_BYPASS", "IDENTITY_SPOOFING")) {
            return "AUTH_BYPASS";
        }
        if (containsAny(text, "WEAK_SESSION_MANAGEMENT")) {
            return "COOKIE_SECURITY";
        }
        if (containsAny(text, "IDOR", "INSECURE_DIRECT_OBJECT_REFERENCE")) {
            return "IDOR";
        }
        if (containsAny(text, "SQL_INJECTION", "SQLI")) {
            return "SQL_INJECTION";
        }
        if (containsAny(text, "SSRF", "SERVER_SIDE_REQUEST_FORGERY")) {
            return "SSRF";
        }
        if (containsAny(text, "COMMAND_INJECTION", "COMMAND_EXECUTION")) {
            return "COMMAND_INJECTION";
        }
        if (containsAny(text, "SCRIPT_INJECTION", "NASHORN", "GROOVY")) {
            return "SCRIPT_INJECTION";
        }
        if (containsAny(text, "DYNAMIC_CLASS_LOADING", "UNSAFE_CLASS_LOADING",
                "CLASSLOADER", "CLASS_LOADER")) {
            return "UNSAFE_CLASS_LOADING";
        }
        if (containsAny(text, "EXPRESSION_INJECTION", "SPEL", "MVEL", "OGNL",
                "QLEXPRESS")) {
            return "EXPRESSION_INJECTION";
        }
        if (containsAny(text, "TEMPLATE_INJECTION", "SSTI", "FREEMARKER",
                "VELOCITY")) {
            return "TEMPLATE_INJECTION";
        }
        if (containsAny(text, "DESERIALIZATION", "DESERIALISATION",
                "FASTJSON", "XSTREAM")) {
            return "DESERIALIZATION";
        }
        if (containsAny(text, "XXE", "XML_EXTERNAL_ENTITY")) {
            return "XXE";
        }
        if (containsAny(text, "XSS", "CROSS_SITE_SCRIPTING")) {
            return "XSS";
        }
        if (containsAny(text, "CRLF", "HTTP_HEADER_INJECTION",
                "HTTP_OUTPUT_INJECTION")) {
            return "CRLF_INJECTION";
        }
        if (containsAny(text, "OPEN_REDIRECT", "UNVALIDATED_REDIRECT")) {
            return "OPEN_REDIRECT";
        }
        if (containsAny(text, "CORS_MISCONFIG", "CORS_MISCONFIGURATION",
                "REFLECTED_ORIGIN")) {
            return "CORS_MISCONFIG";
        }
        if (containsAny(text, "JSONP", "JSONP_HIJACK")) {
            return "JSONP_HIJACK";
        }
        if (containsAny(text, "PATH_TRAVERSAL", "ARBITRARY_FILE_ACCESS",
                "ARBITRARY_FILE_READ")) {
            return "PATH_TRAVERSAL";
        }
        if (containsAny(text, "FILE_UPLOAD", "UNRESTRICTED_UPLOAD")) {
            return "FILE_UPLOAD";
        }
        if (containsAny(text, "CSRF", "CROSS_SITE_REQUEST_FORGERY")) {
            return "CSRF";
        }
        if (containsAny(text, "JWT", "TOKEN_FORGERY", "WEAK_SECRET")) {
            return "JWT_WEAKNESS";
        }
        if (containsAny(text, "COOKIE_SECURITY", "HTTPONLY", "SAMESITE")) {
            return "COOKIE_SECURITY";
        }
        if (containsAny(text, "LOG4SHELL", "LOG4J")) {
            return "LOG4SHELL";
        }
        if (containsAny(text, "ACTUATOR_EXPOSURE", "ACTUATOR")) {
            return "ACTUATOR_EXPOSURE";
        }
        if (containsAny(text, "COMPONENT_OR_CONFIGURATION_VULNERABILITY",
                "COMPONENT_VULN", "CVE")) {
            return "COMPONENT_VULN";
        }
        return "";
    }

    private static String normalizeToken(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.strip()
                .toUpperCase(Locale.ROOT)
                .replaceAll("[^A-Z0-9]+", "_")
                .replaceAll("_+", "_")
                .replaceAll("^_|_$", "");
    }

    private static boolean containsAny(String text, String... needles) {
        for (String needle : needles) {
            if (text.contains(needle)) {
                return true;
            }
        }
        return false;
    }
}
