package com.bpg.authorization.server;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

/**
 * @author zhaohq
 */
@Slf4j
@EnableFeignClients("com.bpg.authorization.server.feign")
@SpringBootApplication
public class AgileAuthorizationServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(AgileAuthorizationServerApplication.class, args);
        log.info("启动成功");
    }

}
