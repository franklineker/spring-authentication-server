package com.frank.authorization_server.repository;

import com.frank.authorization_server.entity.OAuth2Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuth2ClientRepository extends JpaRepository<OAuth2Client, Integer> {
    Optional<OAuth2Client> findByClientId(String clientId);
}
