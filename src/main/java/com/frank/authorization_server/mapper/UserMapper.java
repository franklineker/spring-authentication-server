package com.frank.authorization_server.mapper;

import com.frank.authorization_server.entity.Client;
import com.frank.authorization_server.entity.User;
import com.frank.authorization_server.web.dto.UserRequestDTO;
import com.frank.authorization_server.web.dto.UserResponseDTO;
import lombok.NoArgsConstructor;

@NoArgsConstructor
public class UserMapper {

    public static User toUser(UserRequestDTO dto, Client client){
        return dto != null ? User.builder()
                .username(dto.getUsername())
                .password(dto.getPassword())
                .provider(dto.getProvider())
                .providerId(dto.getProviderId())
                .roles(dto.getRoles())
                .clientRef(client)
                .build() : null;
    }

    public static UserResponseDTO toUserResponseDTO(User user){
        return user != null ? UserResponseDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .clientRefId(user.getClientRef().getId())
                .provider(user.getProvider())
                .providerId(user.getProviderId())
                .roles(user.getRoles())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .disabled(user.isDisabled())
                .expired(user.isExpired())
                .credentialsExpired(user.isCredentialsExpired())
                .locked(user.isLocked())
                .build() : null;
    }
}
