package com.bpg.authorization.server.configuration.redis;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.bpg.spring.boot.security.entity.Md5TokenHolder;
import com.bpg.spring.boot.security.entity.TokenHolder;
import com.bpg.spring.boot.security.store.CustomerTokenStore;
import lombok.RequiredArgsConstructor;
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

    @Override
    public Md5TokenHolder save(TokenHolder tokenHolder, Long accessTokenStoreSeconds, Long refreshTokenStoreSeconds) {
        CharSequence accessTokenMd5 = md5Generator.generateMd5CharSequence(tokenHolder.getAccessToken());
        CharSequence refreshTokenMd5 = md5Generator.generateMd5CharSequence(tokenHolder.getRefreshToken());
        Md5TokenHolder md5TokenHolder = Md5TokenHolder.of(accessTokenMd5.toString(), refreshTokenMd5.toString());
        String jsonString = JSON.toJSONString(tokenHolder);
        redisTemplate.opsForValue().set("AccessToken:" + md5TokenHolder.getAccessToken(), jsonString);
        redisTemplate.expire("AccessToken:" + md5TokenHolder.getAccessToken(), accessTokenStoreSeconds, TimeUnit.SECONDS);

        redisTemplate.opsForValue().set("RefreshToken:" + md5TokenHolder.getRefreshToken(), jsonString);
        redisTemplate.expire("RefreshToken:" + md5TokenHolder.getRefreshToken(), refreshTokenStoreSeconds, TimeUnit.SECONDS);
        return md5TokenHolder;
    }

    @Override
    public TokenHolder find(Md5TokenHolder tokenHolder) {
        String s = redisTemplate.opsForValue().get("AccessToken:" + tokenHolder.getAccessToken());
        if (s != null) {
            return parse(s);
        }
        s = redisTemplate.opsForValue().get("RefreshToken:" + tokenHolder.getRefreshToken());
        if (s != null) {
            return parse(s);
        }
        return TokenHolder.of(null, null);
    }

    @Override
    public void remove(Md5TokenHolder md5TokenHolder) {
        redisTemplate.delete("AccessToken:" + md5TokenHolder.getAccessToken());
        redisTemplate.delete("RefreshToken:" + md5TokenHolder.getRefreshToken());
    }

    private TokenHolder parse(String json) {
        JSONObject jsonObject = JSON.parseObject(json);
        Object accessToken = jsonObject.get("accessToken");
        Object refreshToken = jsonObject.get("refreshToken");
        return TokenHolder.of(accessToken.toString(), refreshToken.toString());
    }
}
