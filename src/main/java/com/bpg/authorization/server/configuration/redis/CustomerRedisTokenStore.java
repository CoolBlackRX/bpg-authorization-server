package com.bpg.authorization.server.configuration.redis;

import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.bpg.spring.boot.security.entity.Md5TokenHolder;
import com.bpg.spring.boot.security.entity.TokenContainer;
import com.bpg.spring.boot.security.entity.TokenHolder;
import com.bpg.spring.boot.security.model.AgileUserDetail;
import com.bpg.spring.boot.security.store.CustomerTokenStore;
import com.bpg.spring.boot.security.store.TokenStoreKey;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * @author zhaohq
 * create time: 2023/10/11 16:03:57
 */
@Component
@RequiredArgsConstructor
public class CustomerRedisTokenStore implements CustomerTokenStore {
    private final RedisTemplate<String, String> redisTemplate;
    private final Md5Generator md5Generator = new SpringMd5Generator();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Md5TokenHolder save(AgileUserDetail agileUserDetail, String clientId, TokenHolder tokenHolder, Long accessTokenStoreSeconds, Long refreshTokenStoreSeconds) {
        CharSequence accessTokenMd5 = md5Generator.generateMd5CharSequence(tokenHolder.getAccessToken());
        CharSequence refreshTokenMd5 = md5Generator.generateMd5CharSequence(tokenHolder.getRefreshToken());
        Md5TokenHolder md5TokenHolder = Md5TokenHolder.of(accessTokenMd5.toString(), refreshTokenMd5.toString(), agileUserDetail.getUserName());
        // md5 token 和 jwt token 都冗余保存到 redis
        TokenContainer tokenContainer = TokenContainer.of(tokenHolder, md5TokenHolder, agileUserDetail.getUserName());
        String jsonString = JSON.toJSONString(tokenContainer);
        redisTemplate.opsForValue().set(TokenStoreKey.Md5_AccessToken + md5TokenHolder.getAccessToken(), jsonString);
        redisTemplate.expire(TokenStoreKey.Md5_AccessToken + md5TokenHolder.getAccessToken(), accessTokenStoreSeconds, TimeUnit.SECONDS);

        redisTemplate.opsForValue().set(TokenStoreKey.Md5_RefreshToken + md5TokenHolder.getRefreshToken(), jsonString);
        redisTemplate.expire(TokenStoreKey.Md5_RefreshToken + md5TokenHolder.getRefreshToken(), refreshTokenStoreSeconds, TimeUnit.SECONDS);

        redisTemplate.opsForValue().set(TokenStoreKey.Jwt_AccessToken + tokenHolder.getAccessToken(), jsonString);
        redisTemplate.expire(TokenStoreKey.Jwt_AccessToken + tokenHolder.getAccessToken(), accessTokenStoreSeconds, TimeUnit.SECONDS);

        redisTemplate.opsForValue().set(TokenStoreKey.Jwt_RefreshToken + tokenHolder.getRefreshToken(), jsonString);
        redisTemplate.expire(TokenStoreKey.Jwt_RefreshToken + tokenHolder.getRefreshToken(), refreshTokenStoreSeconds, TimeUnit.SECONDS);

        // 存储用户映射
        String key = TokenStoreKey.User_Token_Container + clientId + ":" + agileUserDetail.getUserName();
        redisTemplate.opsForValue().set(key, jsonString);
        redisTemplate.expire(key, accessTokenStoreSeconds, TimeUnit.SECONDS);
        return md5TokenHolder;
    }

    @Override
    public TokenContainer find(Md5TokenHolder tokenHolder) {
        String s = redisTemplate.opsForValue().get(TokenStoreKey.Md5_AccessToken + tokenHolder.getAccessToken());
        if (s != null) {
            return parse(s);
        }
        s = redisTemplate.opsForValue().get(TokenStoreKey.Md5_RefreshToken + tokenHolder.getRefreshToken());
        if (s != null) {
            return parse(s);
        }
        return TokenContainer.of(null, null, null);
    }

    @Override
    public TokenContainer findByJwtToken(TokenHolder tokenHolder) {
        String s = redisTemplate.opsForValue().get(TokenStoreKey.Jwt_AccessToken + tokenHolder.getAccessToken());
        if (s != null) {
            return parse(s);
        }
        s = redisTemplate.opsForValue().get(TokenStoreKey.Jwt_RefreshToken + tokenHolder.getRefreshToken());
        if (s != null) {
            return parse(s);
        }
        return TokenContainer.of(null, null, null);
    }

    @Override
    public TokenContainer findByUserName(String userName, String clientId) {
        String key = TokenStoreKey.User_Token_Container + clientId + ":" + userName;
        String s = redisTemplate.opsForValue().get(key);
        if (StrUtil.isEmpty(s)) {
            return null;
        }
        return parse(s);
    }

    @Override
    public void remove(TokenContainer tokenContainer, String userName, String clientId) {
        TokenHolder jwtToken = tokenContainer.getJwtToken();
        if (jwtToken != null && jwtToken.getAccessToken() != null) {
            redisTemplate.delete(TokenStoreKey.Jwt_AccessToken + jwtToken.getAccessToken());
        }
        if (jwtToken != null && jwtToken.getRefreshToken() != null) {
            redisTemplate.delete(TokenStoreKey.Jwt_RefreshToken + jwtToken.getRefreshToken());
        }
        Md5TokenHolder md5Token = tokenContainer.getMd5Token();
        if (md5Token != null && md5Token.getAccessToken() != null) {
            redisTemplate.delete(TokenStoreKey.Md5_AccessToken + md5Token.getAccessToken());
        }
        if (md5Token != null && md5Token.getRefreshToken() != null) {
            redisTemplate.delete(TokenStoreKey.Md5_RefreshToken + md5Token.getRefreshToken());
        }
        if (StrUtil.isAllNotEmpty(userName, clientId)) {
            redisTemplate.delete(TokenStoreKey.User_Token_Container + clientId + ":" + userName);
        }
    }

    private TokenContainer parse(String jsonString) {
        try {
            return objectMapper.readValue(jsonString, TokenContainer.class);
        } catch (JsonProcessingException e) {
            return TokenContainer.of(null, null, null);
        }
    }
}
