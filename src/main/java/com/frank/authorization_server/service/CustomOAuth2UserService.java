package com.frank.authorization_server.service;

// CustomOAuth2UserService.java

import com.frank.authorization_server.entity.CustomOAuth2User;
import com.frank.authorization_server.entity.User;
import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserService userService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = new DefaultOAuth2UserService().loadUser(userRequest);
        System.out.println("custom loadUser() was called!");

        User userFromDb = userService.processOAuth2User(oauth2User, userRequest.getClientRegistration().getClientId());

        return new CustomOAuth2User(
                userFromDb.getId(),
                userFromDb.getClientRef().getId(),
                userFromDb.getUsername(),
                userFromDb.getPassword(),
                userFromDb.getAuthorities(),
                oauth2User.getAttributes()
        );
    }

}
