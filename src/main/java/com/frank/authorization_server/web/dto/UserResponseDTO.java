package com.frank.authorization_server.web.dto;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.ZonedDateTime;
import java.util.Set;
import java.util.UUID;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserResponseDTO {

    private UUID id;
    @NotNull
    private String username;
    private String provider;
    private String providerId;
    @NotNull
    private UUID clientRefId;
    @NotNull
    private Set<String> roles;
    private boolean expired;
    private boolean locked;
    private boolean credentialsExpired;
    private boolean disabled;
    private ZonedDateTime createdAt;
    private ZonedDateTime updatedAt;
}