package org.example.authorizationserver.client.mapper;

import lombok.experimental.UtilityClass;
import org.example.authorizationserver.client.entity.Client;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@UtilityClass
public class ClientMapper {

    public static Client registeredClientToClient(RegisteredClient registeredClient) {
        return null;
    }

    public static RegisteredClient clientToRegisteredClient(Client registeredClient) {
        return null;
    }
}
