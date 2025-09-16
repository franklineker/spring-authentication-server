package com.frank.authorization_server.entity;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;
import java.util.UUID;

@Getter
@Setter
public class CustomOAuth2User implements OAuth2User, UserDetails {

    private final UUID userId;
    private final UUID clientRefId;
    private final String username;
    private final String password;
    private final Collection<? extends GrantedAuthority> authorities;
    private final Map<String, Object> attributes;

    public CustomOAuth2User(UUID userId, UUID clientRefId, String username, String password, Collection<? extends GrantedAuthority> authorities, Map<String, Object> attributes) {
        this.userId = userId;
        this.clientRefId = clientRefId;
        this.username = username;
        this.password = password;
        this.authorities = authorities;
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getName() {
        return username;
    }

    // Métodos de UserDetails
    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }
}
