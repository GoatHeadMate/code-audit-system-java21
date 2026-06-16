package com.huawei.audit.source.impl;

import com.huawei.audit.analysis.EntryPointDiscoverer;
import com.huawei.audit.analysis.EntryPointSelector;
import com.huawei.audit.source.InterfaceInventoryService;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class InterfaceInventoryServiceImpl
        implements InterfaceInventoryService {
    private final List<EntryPointDiscoverer> discoverers;

    public InterfaceInventoryServiceImpl(
            List<EntryPointDiscoverer> discoverers
    ) {
        this.discoverers = List.copyOf(discoverers);
    }

    @Override
    public List<InterfaceSummary> scan(Path sourceRoot) throws Exception {
        Map<String, InterfaceSummary> summaries = new LinkedHashMap<>();
        for (EntryPointDiscoverer discoverer : discoverers) {
            for (var entryPoint : discoverer.discover(sourceRoot)) {
                if (!EntryPointSelector.selectable(entryPoint.protocol())) {
                    continue;
                }
                String id = EntryPointSelector.id(entryPoint);
                summaries.putIfAbsent(id, new InterfaceSummary(
                        id,
                        entryPoint.protocol(),
                        entryPoint.operations(),
                        entryPoint.route(),
                        entryPoint.className(),
                        entryPoint.methodName(),
                        entryPoint.filePath(),
                        entryPoint.startLine(),
                        entryPoint.framework(),
                        entryPoint.securityAnnotations()
                ));
            }
        }
        List<InterfaceSummary> result = new ArrayList<>(summaries.values());
        result.sort(Comparator
                .comparing(InterfaceSummary::route)
                .thenComparing(summary -> String.join(",", summary.operations()))
                .thenComparing(InterfaceSummary::filePath)
                .thenComparingInt(InterfaceSummary::startLine));
        return List.copyOf(result);
    }
}
