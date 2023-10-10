package com.bpg.authorization.server;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author zhaohq
 */
@Slf4j
@SpringBootApplication
public class AgileAuthorizationServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AgileAuthorizationServerApplication.class, args);
        log.info("启动成功");
    }

}
