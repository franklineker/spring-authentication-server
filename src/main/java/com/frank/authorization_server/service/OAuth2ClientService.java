package com.frank.authorization_server.service;

import com.frank.authorization_server.entity.Client;
import com.frank.authorization_server.entity.OAuth2Client;
import com.frank.authorization_server.mapper.OAuth2ClientMapper;
import com.frank.authorization_server.repository.ClientRepository;
import com.frank.authorization_server.repository.OAuth2ClientRepository;
import com.frank.authorization_server.web.dto.OAuth2ClientRequestDTO;
import com.frank.authorization_server.web.dto.OAuth2ClientResponseDTO;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@AllArgsConstructor
public class OAuth2ClientService implements RegisteredClientRepository {

    private final OAuth2ClientRepository oAuth2ClientRepository;
    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public OAuth2ClientResponseDTO saveOAuth2Client(@Valid OAuth2ClientRequestDTO request) {
        Client client = clientRepository.findById(request.getClientRefId())
                .orElseThrow(() -> new RuntimeException(String.format("Client with id %s not found", request.getClientRefId())));
        OAuth2Client oAuth2Client = OAuth2ClientMapper.toOAuth2Client(request, client);
        oAuth2Client.setClientSecret(passwordEncoder.encode(request.getClientSecret()));

        return OAuth2ClientMapper.toOAuth2ClientResponseDTO(oAuth2ClientRepository.save(oAuth2Client));
    }

    @Override
    public void save(RegisteredClient registeredClient) {

    }

    @Override
    public RegisteredClient findById(String id) {
        OAuth2Client client = oAuth2ClientRepository.findByClientId(id).orElseThrow(() -> new RuntimeException("Client not found."));
        System.out.println(client);
        return OAuth2ClientMapper.toRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {

        Optional<OAuth2Client> clientOpt;
        try {
            clientOpt = oAuth2ClientRepository.findByClientId(clientId);
        } catch (Exception e) {
            throw e;
        }

        OAuth2Client oAuth2Client = clientOpt.orElseThrow(() -> new RuntimeException("Client Not Found"));
        return OAuth2ClientMapper.toRegisteredClient(oAuth2Client);
    }
}
