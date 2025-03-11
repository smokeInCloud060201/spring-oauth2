package org.example.authorizationserver.client.repository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.authorizationserver.client.entity.Client;
import org.example.authorizationserver.client.mapper.ClientMapper;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
@Order
public class RegistrationClientRepository implements RegisteredClientRepository {
    private final ClientJPARepository clientJPARepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        log.info("Saving registered client: {}", registeredClient);

        Client client = ClientMapper.registeredClientToClient(registeredClient);

        clientJPARepository.save(client);
    }

    @Override
    public RegisteredClient findById(String id) {
        return clientJPARepository.findById(Long.valueOf(id))
                .map(ClientMapper::clientToRegisteredClient)
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return clientJPARepository.findByClientId(clientId)
                .map(ClientMapper::clientToRegisteredClient)
                .orElse(null);
    }
}
