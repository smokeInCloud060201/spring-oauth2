package org.example.authorizationserver.utils;

import lombok.experimental.UtilityClass;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

@UtilityClass
public class KeyPairGeneratorUtils {

    public static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to generate RSA key pair", e);
        }
    }
}
