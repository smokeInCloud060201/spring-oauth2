package org.example.authorizationserver.dto;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class AuthenticationResponse {
    private String accessToken;
    private String refreshToken;
    private long expiredTime;
}
