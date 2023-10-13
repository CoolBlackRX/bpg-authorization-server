package com.bpg.authorization.server.configuration.handlers;

import com.bpg.spring.boot.security.entity.Md5TokenHolder;
import com.bpg.spring.boot.security.entity.TokenHolder;
import com.bpg.spring.boot.security.model.AgileUserDetail;
import com.bpg.spring.boot.security.store.CustomerTokenStore;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.function.BiFunction;

/**
 * @author zhaohq
 * create time: 2023/10/12 11:26:13
 */
@Component
@RequiredArgsConstructor
public class CustomerMd5TokenConverter implements UserTokenConsumer<AgileUserDetail, RegisteredClient, TokenHolder, Md5TokenHolder> {
    private final CustomerTokenStore customerTokenStore;

    @Override
    public Md5TokenHolder apply(AgileUserDetail agileUserDetail, RegisteredClient registeredClient, TokenHolder tokenHolder) {
        // token md5化之后 存储到redis,并设置过期时间
        TokenSettings tokenSettings = registeredClient.getTokenSettings();
        Duration accessTokenTimeToLive = tokenSettings.getAccessTokenTimeToLive();
        long accessTokenStoreSeconds = accessTokenTimeToLive.getSeconds();
        Duration refreshTokenTimeToLive = tokenSettings.getRefreshTokenTimeToLive();
        long refreshTokenStoreSeconds = refreshTokenTimeToLive.getSeconds();
        return customerTokenStore.save(agileUserDetail, registeredClient.getClientId(), tokenHolder, accessTokenStoreSeconds, refreshTokenStoreSeconds);
    }
}
