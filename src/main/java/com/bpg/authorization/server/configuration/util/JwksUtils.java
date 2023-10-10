package com.bpg.authorization.server.configuration.util;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

public final class JwksUtils {

    private JwksUtils() {
    }

    /**
     * 生成RSA加密key (即JWK)
     */
    public static RSAKey generateRsa() {
        // 生成RSA加密的key
        KeyPair keyPair = KeyGeneratorUtils.generateRsaKey();
        // 公钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        // 私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        // 构建RSA加密key
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    /**
     * 生成EC加密key (即JWK)
     */
    public static ECKey generateEc() {
        // 生成EC加密的key
        KeyPair keyPair = KeyGeneratorUtils.generateEcKey();
        // 公钥
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        // 私钥
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        // 根据公钥参数生成曲线
        Curve curve = Curve.forECParameterSpec(publicKey.getParams());
        // 构建EC加密key
        return new ECKey.Builder(curve, publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    /**
     * 生成HmacSha256密钥
     */
    public static OctetSequenceKey generateSecret() {
        SecretKey secretKey = KeyGeneratorUtils.generateSecretKey();
        return new OctetSequenceKey.Builder(secretKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }
}


