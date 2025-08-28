package com.frank.authorization_server.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.thymeleaf.expression.Uris;

@Configuration
@ConfigurationProperties(prefix = "config")
@Data
public class AppConfig {
    private Uris uris;

    @Data
    public static class Uris {
        private String reactAppUri;
        private String loginUri;
        private String logoutUri;
    }
}
