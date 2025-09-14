package com.frank.authorization_server.service;

import com.frank.authorization_server.entity.Client;
import com.frank.authorization_server.entity.OAuth2Client;
import com.frank.authorization_server.entity.User;
import com.frank.authorization_server.mapper.UserMapper;
import com.frank.authorization_server.repository.ClientRepository;
import com.frank.authorization_server.repository.OAuth2ClientRepository;
import com.frank.authorization_server.repository.UserRepository;
import com.frank.authorization_server.web.dto.OAuth2ClientRequestDTO;
import com.frank.authorization_server.web.dto.UserRequestDTO;
import com.frank.authorization_server.web.dto.UserResponseDTO;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.UUID;


@AllArgsConstructor
@Service
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final ClientRepository clientRepository;
    private final OAuth2ClientRepository oAuth2ClientRepository;

    @Transactional
    public UserResponseDTO createUser(@Valid UserRequestDTO dto){

        String passwordEncoded = passwordEncoder.encode(dto.getPassword());
        dto.setPassword(passwordEncoded);

        Client client = clientRepository.findById(dto.getClientRefId())
                .orElseThrow(() -> new RuntimeException(String.format("Client with id %s not found.", dto.getClientRefId())));

        User user = userRepository.save(UserMapper.toUser(dto,client));

        return UserMapper.toUserResponseDTO(user);
    }

    // UserService.java

    @Transactional
    public User processOAuth2User(OAuth2User oauth2User, String clientId) {
        String email = oauth2User.getAttribute("email");

        // Busca o OAuth2Client com base no clientId fornecido
        OAuth2Client oAuth2Client = oAuth2ClientRepository.findByClientId(clientId)
                .orElseThrow(() -> new RuntimeException("OAuth2Client not found with the provided client_id"));

        String providerId = oauth2User.getAttribute("sub");
        String provider = "google";

        return userRepository.findByUsername(email)
                .orElseGet(() -> {
                    // Usa o Client_Ref associado ao OAuth2Client
                    Client client = clientRepository.findById(oAuth2Client.getClientRef().getId())
                            .orElseThrow(() -> new RuntimeException("Client reference not found."));

                    User newUser = User.builder()
                            .username(email)
                            .password(passwordEncoder.encode("default-password"))
                            .provider(provider)
                            .providerId(providerId)
                            .clientRef(client)
                            .roles(Set.of("USER"))
                            .build();

                    return userRepository.save(newUser);
                });
    }
}
