package com.frank.authorization_server;

import com.frank.authorization_server.security.OAuth2TokenProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

@EnableConfigurationProperties(OAuth2TokenProperties.class)
@SpringBootApplication
@ComponentScan(basePackages = "com.frank.authorization_server")
public class AuthorizationServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServerApplication.class, args);
	}

}
