package org.example.authorizationserver.client.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.example.authorizationserver.util.JsonUtil;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

@Converter
public class TokenSettingConverter implements AttributeConverter<TokenSettings, String> {
    @Override
    public String convertToDatabaseColumn(TokenSettings attribute) {
        try {
            return JsonUtil.stringify(attribute);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public TokenSettings convertToEntityAttribute(String dbData) {
        try {
            return JsonUtil.getObjectFromJsonString(TokenSettings.class, dbData);
        } catch (Exception e) {
            return null;
        }
    }
}
