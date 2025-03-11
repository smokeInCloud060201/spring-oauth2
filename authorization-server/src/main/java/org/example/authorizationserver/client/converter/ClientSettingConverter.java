package org.example.authorizationserver.client.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.example.authorizationserver.util.JsonUtil;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

@Converter
public class ClientSettingConverter implements AttributeConverter<ClientSettings, String> {
    @Override
    public String convertToDatabaseColumn(ClientSettings attribute) {
        try {
            return JsonUtil.stringify(attribute);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public ClientSettings convertToEntityAttribute(String dbData) {
        try {
            return JsonUtil.getObjectFromJsonString(ClientSettings.class, dbData);
        } catch (Exception e) {
            return null;
        }
    }
}
