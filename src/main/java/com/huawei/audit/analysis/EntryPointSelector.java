package com.huawei.audit.analysis;

import com.huawei.audit.analysis.EntryPointDiscoverer.DiscoveredEntryPoint;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.EntryPoint;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

public final class EntryPointSelector {
    private EntryPointSelector() {
    }

    public static String id(DiscoveredEntryPoint entryPoint) {
        return id(
                entryPoint.protocol(),
                entryPoint.operations(),
                entryPoint.route(),
                entryPoint.className(),
                entryPoint.methodName(),
                entryPoint.filePath()
        );
    }

    public static String id(EntryPoint entryPoint) {
        return id(
                entryPoint.protocol(),
                entryPoint.httpMethods(),
                entryPoint.path(),
                entryPoint.className(),
                entryPoint.methodName(),
                entryPoint.filePath()
        );
    }

    public static boolean selectable(String protocol) {
        return "HTTP".equalsIgnoreCase(protocol)
                || "WEBSOCKET".equalsIgnoreCase(protocol);
    }

    private static String id(
            String protocol,
            List<String> operations,
            String route,
            String className,
            String methodName,
            String filePath
    ) {
        String canonical = String.join(
                "\n",
                safe(protocol).toUpperCase(),
                operations.stream().sorted().toList().toString(),
                safe(route),
                safe(className),
                safe(methodName),
                safe(filePath).replace('\\', '/')
        );
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(canonical.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 12);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
