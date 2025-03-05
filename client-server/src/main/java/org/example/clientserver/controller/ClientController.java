package org.example.clientserver.controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Collections;
import java.util.Map;

import static org.springframework.security.oauth2.client.web.client.RequestAttributeClientRegistrationIdResolver.clientRegistrationId;

@RestController
@RequestMapping("/client")
public class ClientController {


    @Autowired
    private OAuth2AuthorizedClientService clientService;

    @Autowired
    private WebClient webClient;

    @GetMapping("/")
    public String home() {
        return "Welcome to the Client Server";
    }

    @GetMapping("/user")
    public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal) {
        return Collections.singletonMap("name", principal.getAttribute("name"));
    }

    @GetMapping("/fetch-user-resource")
    public Map<String, String> fetchUserResource(OAuth2AuthenticationToken authentication) {
        return webClient
                .get()
                .uri("http://localhost:8082/api/user/data")
                .attributes(clientRegistrationId("user-client"))
                .retrieve()
                .bodyToMono(Map.class)
                .block();
    }

    @GetMapping("/fetch-machine-resource")
    public Map<String, String> fetchMachineResource() {
        return webClient
                .get()
                .uri("http://localhost:8082/api/machine/data")
                .attributes(clientRegistrationId("machine-client"))
                .retrieve()
                .bodyToMono(Map.class)
                .block();
    }
}