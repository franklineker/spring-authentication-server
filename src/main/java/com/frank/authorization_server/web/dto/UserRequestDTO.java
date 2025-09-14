package com.frank.authorization_server.web.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.validation.annotation.Validated;

import java.time.ZonedDateTime;
import java.util.Set;
import java.util.UUID;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserRequestDTO {
   @NotNull
   @Email(message = "Not a valid email.")
   private String username;
   private String password;
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
