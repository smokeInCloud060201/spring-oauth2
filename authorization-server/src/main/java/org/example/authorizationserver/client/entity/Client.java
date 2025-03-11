package org.example.authorizationserver.client.entity;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Converter;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import org.example.authorizationserver.base.BaseEntity;
import org.example.authorizationserver.client.converter.ClientSettingConverter;
import org.hibernate.annotations.SQLRestriction;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.bind.annotation.GetMapping;

import java.time.Instant;
import java.util.Set;

@Table(name = "client")
@Getter
@Setter
@Entity
@SQLRestriction("is_deleted = false")
public class Client extends BaseEntity {
    @Column(name = "client_id")
    private String clientId;

    @Column(name = "client_id_issue_at")
    private Instant clientIdIssuedAt;

    @Column(name = "client_secret")
    private String clientSecret;

    @Column(name = "client_secret_expires_at")
    private Instant clientSecretExpiresAt;

    @Column(name = "client_name")
    private String clientName;

    @ElementCollection(targetClass = ClientAuthenticationMethod.class, fetch = FetchType.LAZY)
    @CollectionTable(name = "client_authentication_method", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "authentication_method")
    private Set<ClientAuthenticationMethod> clientAuthenticationMethods;

    @ElementCollection(targetClass = AuthorizationGrantType.class, fetch = FetchType.LAZY)
    @CollectionTable(name = "authorization_grant_type", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "authorization_type", nullable = false)
    private Set<AuthorizationGrantType> authorizationGrantTypes;

    @ElementCollection(targetClass = String.class, fetch = FetchType.LAZY)
    @CollectionTable(name = "redirect_url", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "url", nullable = false)
    private Set<String> redirectUris;

    @ElementCollection(targetClass = String.class, fetch = FetchType.LAZY)
    @CollectionTable(name = "redirect_url", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "url", nullable = false)
    private Set<String> postLogoutRedirectUris;

    @ElementCollection(targetClass = String.class, fetch = FetchType.LAZY)
    @CollectionTable(name = "scopes", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "scope", nullable = false)
    private Set<String> scopes;

    @Convert(converter = ClientSettingConverter.class)
    @Column(name = "client_setting", columnDefinition = "TEXT")
    private ClientSettings clientSetting;

    @Convert(converter = ClientSettingConverter.class)
    @Column(name = "token_setting", columnDefinition = "TEXT")
    private TokenSettings tokenSettings;
}
