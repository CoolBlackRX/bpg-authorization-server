package com.bpg.authorization.server.configuration.redis;

import com.bpg.spring.boot.security.store.CustomerRedisConnectFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.stereotype.Component;

/**
 * @author zhaohq
 * create time: 2023/10/11 16:52:24
 */
@Component
@RequiredArgsConstructor
public class CustomerRedisConnectionImpl implements CustomerRedisConnectFactory {
    private final RedisConnectionFactory redisConnectionFactory;

    @Override
    public RedisConnectionFactory getConnectionFactory() {
        return redisConnectionFactory;
    }
}
