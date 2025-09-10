package com.frank.authorization_server.mapper;

import com.frank.authorization_server.entity.User;
import com.frank.authorization_server.web.dto.UserDTO;
import lombok.Builder;
import lombok.NoArgsConstructor;

@NoArgsConstructor
public class UserMapper {

    public static User toUser(UserDTO dto){
        return dto != null ? User.builder()
                .username(dto.getUsername())
                .password(dto.getPassword())
                .provider(dto.getProvider())
                .roles(dto.getRoles())
                .clientRef(dto.getClientRef())
                .build() : null;
    }

    public static UserDTO toUserResponseDTO(User user){
        return user != null ? UserDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .clientRef(user.getClientRef())
                .provider(user.getProvider())
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
