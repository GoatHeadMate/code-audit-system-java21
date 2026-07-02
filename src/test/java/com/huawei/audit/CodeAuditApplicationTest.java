package com.huawei.audit;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;

@SpringBootTest(properties = "audit.workspace=target/test-workspace/code-audit-application-test")
@AutoConfigureMockMvc
class CodeAuditApplicationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void contextLoads() {
    }

    @Test
    void apiErrorsAreAlwaysJson() throws Exception {
        mockMvc.perform(multipart("/audit").param("lang", "java"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.detail").isNotEmpty())
                .andExpect(jsonPath("$.path").value("/audit"));
    }

    @Test
    void healthDescribesTheActiveWhiteBoxEngine() throws Exception {
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.analysis_engine").value("jdk-ast-whitebox"))
                .andExpect(jsonPath("$.scan_strategy").value("candidate-path-whitebox"))
                .andExpect(jsonPath("$.agent_runtime")
                        .value("agentscope-java-harness"))
                .andExpect(jsonPath("$.agent_transport").value("in-process-java"));
    }

    @Test
    void frontendBrandsTheActiveWhiteBoxAgentScopeWorkflow() throws Exception {
        String html = Files.readString(Path.of(
                "src", "main", "resources", "static", "index.html"
        ));

        org.assertj.core.api.Assertions.assertThat(html)
                .contains("Java 白盒分析 + AgentScope")
                .contains("/audit/interfaces")
                .contains("选择检测接口");
    }

    @Test
    void frontendRendersAgentScopeArrayEvidence() throws Exception {
        String html = Files.readString(Path.of(
                "src", "main", "resources", "static", "index.html"
        ));

        org.assertj.core.api.Assertions.assertThat(html)
                .contains("Array.isArray(ev)")
                .contains("renderEvidenceText(item)")
                .doesNotContain("const numbered = ev.match");
    }
}
