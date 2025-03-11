package org.example.authorizationserver.client.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.authorizationserver.client.entity.Client;
import org.example.authorizationserver.client.service.ClientService;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class ClientServiceImpl implements ClientService {
    @Override
    public void addNewClient() {

    }

    @Override
    public void updateClient() {

    }

    @Override
    public void deleteClient() {

    }

    @Override
    public void findClientById() {

    }

    @Override
    public Page<Client> findAllClients() {
        return null;
    }
}
