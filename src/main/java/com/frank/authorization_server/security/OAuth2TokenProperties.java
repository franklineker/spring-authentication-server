package com.frank.authorization_server.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "spring.security.oauth2")
public record OAuth2TokenProperties(Duration accessTokenTtl, Duration refreshTokenTtl) {}
