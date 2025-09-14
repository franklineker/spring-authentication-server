package com.frank.authorization_server.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "oauth2_client")
@Entity
public class OAuth2Client {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;
    @Column(nullable = false, name = "client_id", unique = true)
    private String clientId;
    @ManyToOne(optional = false)
    @JoinColumn(name = "client_ref", nullable = false)
    private Client clientRef;
    @Column(name = "client_secret",nullable = false)
    private String clientSecret;
    @Column(name = "client_id_issued_at")
    private Instant clientIdIssuedAt;
    @Column(name = "authorization_grant_types")
    private Set<String> authorizationGrantTypes;
    @Column(name = "authentication_methods")
    private Set<String> authenticationMethods;
    @Column(name = "redirect_uris")
    private Set<String> redirectUris;
    @Column(name = "scopes")
    private Set<String> scopes;
    @Column(name = "required_proof_key")
    private boolean requireProofKey;

    @Column(name = "require_consent")
    private boolean requireConsent;
}
