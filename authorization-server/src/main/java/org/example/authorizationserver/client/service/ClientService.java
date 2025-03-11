package org.example.authorizationserver.client.service;

import org.example.authorizationserver.client.entity.Client;
import org.springframework.data.domain.Page;

public interface ClientService {
    void addNewClient();

    void updateClient();

    void deleteClient();

    void findClientById();

    Page<Client> findAllClients();
}
