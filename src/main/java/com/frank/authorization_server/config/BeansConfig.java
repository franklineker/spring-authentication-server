package com.frank.authorization_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.time.Duration;

@Configuration
public class BeansConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public String toString() {
        return new String();
    }
    @Bean
    public CorsConfigurationSource corsConfigurationSource( ){
        CorsConfiguration cors = new CorsConfiguration();
        cors.addAllowedOrigin("http://localhost:3000");
        cors.addAllowedOrigin("http://localhost:4200");
        cors.addAllowedOrigin("https://1893-2804-7f0-91c1-bbab-5d52-afd2-1b22-6819.ngrok-free.app");
        cors.addAllowedHeader("*");
        cors.addAllowedMethod("*");
        cors.setAllowCredentials(true);


        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cors);

        return source;
    }

    @Bean
    public CorsFilter corsFilter() {
        return new CorsFilter(corsConfigurationSource());
    }
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

}
