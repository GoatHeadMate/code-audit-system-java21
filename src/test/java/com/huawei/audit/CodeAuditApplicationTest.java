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

@SpringBootTest
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
                .andExpect(jsonPath("$.claude_runtime")
                        .value("python-agent-sdk-sidecar"))
                .andExpect(jsonPath("$.agent_transport").value("http-ndjson"));
    }

    @Test
    void frontendBrandsTheActiveWhiteBoxClaudeWorkflow() throws Exception {
        String html = Files.readString(Path.of(
                "src", "main", "resources", "static", "index.html"
        ));

        org.assertj.core.api.Assertions.assertThat(html)
                .contains("Java 白盒分析 + Claude")
                .contains("/audit/interfaces")
                .contains("选择检测接口");
    }
}
