package com.bpg.authorization.server.configuration.oauth2;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;

import java.util.List;

/**
 * @author zhaohq
 * @date 2022/11/3
 **/
@Data
@ConfigurationProperties(prefix = "oauth2.login-clients")
@RefreshScope
public class Oauth2ClientLoginConfiguration {
    private List<ClientAttribute> clients;

    @Data
    public static class ClientAttribute {
        private String name;
        private String method;
    }
}
