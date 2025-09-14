package com.frank.authorization_server.web.dto;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;
import java.util.UUID;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class OAuth2ClientResponseDTO {

    @NotNull
    private String clientId;
    @NotNull
    private UUID clientRefId;
    @NotNull
    private Set<String> authorizationGrantTypes;
    @NotNull
    private Set<String> authenticationMethods;
    @NotNull
    private Set<String> redirectUris;
    @NotNull
    private Set<String> scopes;
    @NotNull
    private boolean requireProofKey;
    @NotNull
    private boolean requireConsent;

}
