package com.huawei.audit;

import com.huawei.audit.config.AuditProperties;
import com.huawei.audit.config.AgentScopeProperties;
import com.huawei.audit.config.CodeGraphProperties;
import com.huawei.audit.config.OrchestratorProperties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@EnableConfigurationProperties({
        AgentScopeProperties.class,
        AuditProperties.class,
        CodeGraphProperties.class,
        OrchestratorProperties.class
})
public class CodeAuditApplication {

    public static void main(String[] args) {
        SpringApplication.run(CodeAuditApplication.class, args);
    }

    @Bean(destroyMethod = "close")
    ExecutorService virtualThreadExecutor() {
        return Executors.newVirtualThreadPerTaskExecutor();
    }
}
