package com.frank.authorization_server.web.dto;

import com.frank.authorization_server.entity.User;
import jakarta.persistence.Column;
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
public class UserDTO {

   private UUID id;
   @NotNull
   private String username;
   private String password;
   private String provider;
   @NotNull
   private UUID clientRef;
   @NotNull
   private Set<String> roles;
   private boolean expired;
   private boolean locked;
   private boolean credentialsExpired;
   private boolean disabled;
   private ZonedDateTime createdAt;
   private ZonedDateTime updatedAt;

   public UserDTO(String username, String password, String provider, UUID clientRef, Set<String> roles){
      super();
      this.username = username;
      this.password = password;
      this.provider = provider;
      this.clientRef = clientRef;
      this.roles = roles;
   }

}
