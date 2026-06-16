import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
class Controller {
    @PostMapping("/run")
    void run(@RequestBody String command) throws Exception {
        new ProcessBuilder("/bin/bash", "-c", command).start();
    }
}
