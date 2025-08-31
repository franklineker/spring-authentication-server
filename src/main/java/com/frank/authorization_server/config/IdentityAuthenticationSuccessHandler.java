package com.frank.authorization_server.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.function.Consumer;

public class IdentityAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private Consumer<OAuth2User> oAuth2UserHandler = (user) -> {};
    private Consumer<OidcUser> oidcUserHandler = (user) -> this.oAuth2UserHandler.accept(user);
    private final String redirectUri;

    public IdentityAuthenticationSuccessHandler(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        if (authentication instanceof OAuth2AuthenticationToken) {
            if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
                this.oidcUserHandler.accept(oidcUser);
            } else if (authentication.getPrincipal() instanceof OAuth2User oauth2User) {
                this.oAuth2UserHandler.accept(oauth2User);
            }
        }

        response.sendRedirect(redirectUri);
    }

    public void setOAuth2UserHandler(Consumer<OAuth2User> oAuth2UserHandler) {
        this.oAuth2UserHandler = oAuth2UserHandler;
    }

    public Consumer<OAuth2User> getOAuth2UserHandler() {
        return oAuth2UserHandler;
    }

    public void setOidcUserHandler(Consumer<OidcUser> oidcUserHandler) {
        this.oidcUserHandler = oidcUserHandler;
    }
}
