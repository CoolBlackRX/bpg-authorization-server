package com.bpg.authorization.server.configuration.redis;

import org.springframework.util.DigestUtils;

import java.util.Optional;

/**
 * @author zhaohq
 * @date 2023/3/22
 **/
public class SpringMd5Generator implements Md5Generator {

    @Override
    public CharSequence generateMd5CharSequence(String salt) {
        // 三次生成
        String result = DigestUtils.md5DigestAsHex(Optional.ofNullable(salt).orElse("").getBytes());
        result = DigestUtils.md5DigestAsHex(result.getBytes());
        result = DigestUtils.md5DigestAsHex(result.getBytes());
        return result;
    }
}
