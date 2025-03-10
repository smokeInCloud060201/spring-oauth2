package org.example.authorizationserver.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Map;
import java.util.Set;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class JsonUtil {
    private static final String ERROR_MESSAGE = "EXCEPTION WHEN PARSE OBJECT TO STRING {}";
    private static ObjectMapper mapper;
    private static void initialize() {
        if (mapper == null) {
            SimpleModule simpleModule = new SimpleModule();
            mapper = Jackson2ObjectMapperBuilder.json().serializationInclusion(JsonInclude.Include.NON_NULL).failOnEmptyBeans(false).failOnUnknownProperties(false).featuresToEnable(new Object[]{MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY}).featuresToDisable(new Object[]{SerializationFeature.WRITE_DATES_AS_TIMESTAMPS}).modules(new Module[]{new JavaTimeModule()}).build();
        }
    }

    public static void setMapper(Module module) {
        initialize();
        mapper.registerModule(module);
    }

    public static JsonNode convertStringToJsonNode(String jsonString) throws IOException {
        initialize();
        return mapper.readTree(jsonString);
    }

    public static String stringify(Object data) {
        initialize();

        try {
            return mapper.writeValueAsString(data);
        } catch (JsonProcessingException var2) {
            log.error("EXCEPTION WHEN PARSE OBJECT TO STRING {}", var2.getMessage());
            return null;
        }
    }

    public static void stringify(Object data, OutputStream output) {
        initialize();

        try {
            mapper.writeValue(output, data);
        } catch (IOException var3) {
            log.error("EXCEPTION WHEN PARSE OBJECT TO STRING {}", var3.getMessage());
        }

    }

    public static <T> T getObjectFromJsonString(Class<T> clazz, String json) {
        initialize();

        try {
            return mapper.readValue(json, clazz);
        } catch (JsonProcessingException var3) {
            log.error("EXCEPTION WHEN PARSE OBJECT TO STRING {}", var3.getMessage());
            return null;
        }
    }

    public static <T> T getObjectFromJsonString(Class<T> clazz, String json, T defaultValue) {
        initialize();

        try {
            return mapper.readValue(json, clazz);
        } catch (JsonProcessingException var4) {
            log.error("EXCEPTION WHEN PARSE OBJECT TO STRING {}", var4.getMessage());
            return defaultValue;
        }
    }

    public static <T> T getObjectFromJsonString(TypeReference<T> clazz, String json) {
        initialize();

        try {
            return mapper.readValue(json, clazz);
        } catch (JsonProcessingException var3) {
            log.error("EXCEPTION WHEN PARSE OBJECT TO STRING {}", var3.getMessage());
            return null;
        }
    }

    private static <T> T convert(Object obj, TypeReference<T> typeReference) {
        initialize();
        return mapper.convertValue(obj, typeReference);
    }

    public static Map<String, Object> convertToMap(Object obj) {
        return (Map)convert(obj, new TypeReference<Map<String, Object>>() {
        });
    }

    public static Set<String> convertToSet(Object obj) {
        return (Set)convert(obj, new TypeReference<Set<String>>() {
        });
    }
}
