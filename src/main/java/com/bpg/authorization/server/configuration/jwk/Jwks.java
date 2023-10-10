package com.bpg.authorization.server.configuration.jwk;

import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.extern.slf4j.Slf4j;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 * @author zhaohq
 */
@Slf4j
public final class Jwks {

    private Jwks() {
    }

    public static RSAKey generateRsa() {
        KeyPair keyPair = KeyGeneratorUtils.generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .keyUse(KeyUse.SIGNATURE)
                .privateKey(privateKey)
                .keyID("99a2e068-f127-4903-9088-b56ec29b8e8e").build();
    }

    public static void main(String[] args) {
        KeyPair keyPair = KeyGeneratorUtils.generateRsaKey();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        String rsaPublicKeyString = Base64.getEncoder().encodeToString(rsaPublicKey.getEncoded());
        String rsaPrivateKeyString = Base64.getEncoder().encodeToString(rsaPrivateKey.getEncoded());

        System.out.println(rsaPublicKeyString);
        System.out.println(rsaPrivateKeyString);



    }
}
