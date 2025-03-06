package org.example.authorizationserver.controllers;

import lombok.RequiredArgsConstructor;
import org.example.authorizationserver.dto.AuthRequest;
import org.example.authorizationserver.dto.AuthResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final RegisteredClientRepository registeredClientRepository;

    private final PasswordEncoder passwordEncoder;

    private final OAuth2TokenGenerator<OAuth2AccessToken> tokenGenerator;

    @PostMapping("/api/token/machine")
    public Map<String, String> generateMachineToken(@RequestBody Map<String, String> request) {
        String clientId = request.get("client_id");
        String clientSecret = request.get("client_secret");

        // Validate client credentials
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null ||
                !passwordEncoder.matches(clientSecret, registeredClient.getClientSecret()) ||
                !registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.CLIENT_CREDENTIALS)) {
            throw new RuntimeException("Invalid client credentials");
        }

        // Create token generation context
        DefaultOAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();

        // Generate token
        OAuth2AccessToken accessToken = (OAuth2AccessToken) tokenGenerator.generate(tokenContext);

        // Prepare response
        Map<String, String> response = new HashMap<>();
        response.put("access_token", accessToken.getTokenValue());
        response.put("token_type", accessToken.getTokenType().getValue());
        response.put("expires_in", String.valueOf(accessToken.getExpiresAt().toEpochMilli()));
        return response;
    }

    @PostMapping("/api/token/user")
    public Map<String, String> generateUserToken(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");

        // In a real-world scenario, you'd validate against UserDetailsService
        // For this example, we'll use a simple check
        if (!"user".equals(username) || !"password".equals(password)) {
            throw new RuntimeException("Invalid user credentials");
        }

        // Find a client that supports authorization code
        RegisteredClient registeredClient = registeredClientRepository.findByClientId("user-client");

        List<? extends GrantedAuthority> grantedAuthorityMap = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", username);

        // Create token generation context
        DefaultOAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();

        // Generate token
        OAuth2AccessToken accessToken = tokenGenerator.generate(tokenContext);

        // Prepare response
        Map<String, String> response = new HashMap<>();
        response.put("access_token", accessToken.getTokenValue());
        response.put("token_type", accessToken.getTokenType().getValue());
        response.put("expires_in", String.valueOf(accessToken.getExpiresAt().toEpochMilli()));
        return response;
    }
}