package com.frank.authorization_server.web.controller;

import com.frank.authorization_server.service.OAuth2ClientService;
import com.frank.authorization_server.web.dto.OAuth2ClientRequestDTO;
import com.frank.authorization_server.web.dto.OAuth2ClientResponseDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth/oauth2client")
public class OAuth2ClientController {

    @Autowired
    private OAuth2ClientService service;

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<OAuth2ClientResponseDTO> createOAuth2Client(@RequestBody OAuth2ClientRequestDTO request) {
        OAuth2ClientResponseDTO oAuth2ClientDTO = service.saveOAuth2Client(request);
        return ResponseEntity.ok(oAuth2ClientDTO);
    }
}
