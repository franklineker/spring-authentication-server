package com.frank.authorization_server.web.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.time.Instant;
import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class OAuth2ClientRequest {
    private String clientId;
    private String clientSecret;
    private Set<String> authorizationGrantTypes;
    private Set<String> authenticationMethods;
    private Set<String> redirectUris;
    private Set<String> scopes;
    private boolean requireProofKey;
}