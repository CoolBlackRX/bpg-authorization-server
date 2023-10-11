package com.bpg.authorization.server.configuration.redis;

/**
 * @author zhaohq
 * @date 2023/3/22
 **/
public interface Md5Generator {

    /**
     * 构造MD5
     *
     * @param salt 加盐
     * @return CharSequence
     */
    CharSequence generateMd5CharSequence(String salt);
}
