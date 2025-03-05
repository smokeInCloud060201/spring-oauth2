package org.example.authorizationserver.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration
public class AppConfig {

    @Bean
    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> jwtTokenCustomizer() {
        return context -> {

            context.getClaims()
                    .claim(
                            "authorities", "test"
                    )
                    .claim(
                            "username", "test also"
                    );
        };
    }
}
