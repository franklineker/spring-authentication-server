package com.frank.authorization_server.mapper;

import com.frank.authorization_server.entity.User;
import com.frank.authorization_server.web.dto.UserRequest;
import com.frank.authorization_server.web.dto.UserResponse;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
public class UserMapper {

    public static User toUser(UserRequest request) {
        return request != null ? User.builder()
                .username(request.getUsername())
                .password(request.getPassword())
                .roles(request.getRoles())
                .expired(false)
                .credentialsExpired(false)
                .disabled(false)
                .locked(false)
                .build() : null;
    }

    public static UserResponse toUserResponse(User user) {
        return user != null ? UserResponse.builder()
                .username(user.getUsername())
                .roles(user.getRoles())
                .build() : null;
    }

    public static User fromOauth2User(OAuth2User oAuth2User) {
        User user = User.builder()
                .username(oAuth2User.getAttributes().get("email").toString())
                .roles(new ArrayList<>(List.of("CUSTOMER")))
                .build();

        return user;
    }
}
