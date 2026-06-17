package com.huawei.audit.source;

import static org.assertj.core.api.Assertions.assertThat;

import com.huawei.audit.analysis.EntryPointDiscoverer.DiscoveredEntryPoint;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ServletEntryPointDiscovererTest {
    @TempDir
    Path tempDir;

    private List<DiscoveredEntryPoint> discover(String fileName, String source)
            throws Exception {
        Files.writeString(tempDir.resolve(fileName), source);
        return new ServletEntryPointDiscoverer().discover(tempDir);
    }

    @Test
    void discoversHttpServletMethods() throws Exception {
        var entries = discover("MyServlet.java", """
                import jakarta.servlet.http.HttpServlet;
                public class MyServlet extends HttpServlet {
                    protected void doGet(Object req, Object resp) {}
                    protected void doPost(Object req, Object resp) {}
                }
                """);
        assertThat(entries)
                .extracting(entry -> entry.protocol() + " "
                        + entry.operations().getFirst() + " " + entry.methodName())
                .containsExactlyInAnyOrder("HTTP GET doGet", "HTTP POST doPost");
    }

    @Test
    void discoversWebServletRoute() throws Exception {
        var entries = discover("AnnServlet.java", """
                import jakarta.servlet.annotation.WebServlet;
                @WebServlet("/ann")
                public class AnnServlet {
                    public void handle(Object req) {}
                }
                """);
        assertThat(entries).anySatisfy(entry -> {
            assertThat(entry.protocol()).isEqualTo("HTTP");
            assertThat(entry.methodName()).isEqualTo("handle");
            assertThat(entry.route()).isEqualTo("/ann");
        });
    }

    @Test
    void discoversFilter() throws Exception {
        var entries = discover("Gate.java", """
                import jakarta.servlet.Filter;
                public class Gate implements Filter {
                    public void doFilter(Object a, Object b, Object c) {}
                }
                """);
        assertThat(entries)
                .extracting(entry -> entry.protocol() + " " + entry.methodName())
                .contains("HTTP_FILTER doFilter");
    }

    @Test
    void discoversInterceptor() throws Exception {
        var entries = discover("Intc.java", """
                import org.springframework.web.servlet.HandlerInterceptor;
                public class Intc implements HandlerInterceptor {
                    public boolean preHandle(Object a, Object b, Object c) {
                        return true;
                    }
                }
                """);
        assertThat(entries).anySatisfy(entry -> {
            assertThat(entry.protocol()).isEqualTo("HTTP_FILTER");
            assertThat(entry.methodName()).isEqualTo("preHandle");
            assertThat(entry.operations()).containsExactly("INTERCEPTOR");
        });
    }

    @Test
    void discoversWebSocketServerEndpoint() throws Exception {
        var entries = discover("Ws.java", """
                import jakarta.websocket.server.ServerEndpoint;
                import jakarta.websocket.OnMessage;
                @ServerEndpoint("/ws")
                public class Ws {
                    @OnMessage public void onMessage(String message) {}
                }
                """);
        assertThat(entries)
                .extracting(entry -> entry.protocol() + " " + entry.methodName())
                .contains("WEBSOCKET onMessage");
    }

    @Test
    void discoversGrpcImplBase() throws Exception {
        var entries = discover("Greeter.java", """
                public class Greeter extends GreeterGrpc.GreeterImplBase {
                    public void sayHello(Object request, Object observer) {}
                }
                """);
        assertThat(entries)
                .extracting(entry -> entry.protocol() + " " + entry.methodName())
                .contains("GRPC sayHello");
    }

    @Test
    void discoversDubboService() throws Exception {
        var entries = discover("Dub.java", """
                import org.apache.dubbo.config.annotation.DubboService;
                @DubboService
                public class Dub {
                    public String greet(String name) { return name; }
                }
                """);
        assertThat(entries)
                .extracting(entry -> entry.protocol() + " " + entry.methodName())
                .contains("RPC greet");
    }

    @Test
    void discoversLifecycleRunnerAndPostConstruct() throws Exception {
        var entries = discover("Boot.java", """
                import org.springframework.boot.CommandLineRunner;
                import jakarta.annotation.PostConstruct;
                public class Boot implements CommandLineRunner {
                    @PostConstruct public void setup() {}
                    public void run(String... args) {}
                }
                """);
        assertThat(entries)
                .extracting(entry -> entry.protocol() + " "
                        + entry.operations().getFirst() + " " + entry.methodName())
                .contains("LIFECYCLE INIT setup", "LIFECYCLE STARTUP run");
    }
}
