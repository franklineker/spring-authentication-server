package com.frank.authorization_server.web.controller;

import com.frank.authorization_server.entity.OAuth2Client;
import com.frank.authorization_server.service.OAuth2ClientService;
import com.frank.authorization_server.web.dto.OAuth2ClientRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth/oauth2client")
public class OAuth2ClientController {

    @Autowired
    private OAuth2ClientService service;

    @PostMapping(path = "/save", consumes = MediaType.APPLICATION_JSON_VALUE)
    public OAuth2Client createOAuth2Client(@RequestBody OAuth2ClientRequest request) {
        return service.saveClient(request);
    }
}
