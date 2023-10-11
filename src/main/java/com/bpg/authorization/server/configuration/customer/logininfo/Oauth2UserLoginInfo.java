package com.bpg.authorization.server.configuration.customer.logininfo;

import lombok.Data;

import java.time.LocalDateTime;

/**
 * @author zhaohq
 * @date 2022/12/2
 **/
@Data
@com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT)
@com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown = true)
public class Oauth2UserLoginInfo {
    @com.fasterxml.jackson.annotation.JsonProperty("user_id")
    private String userId;
    @com.fasterxml.jackson.annotation.JsonProperty("employee_name")
    private String employeeName;
    @com.fasterxml.jackson.annotation.JsonProperty("client_id")
    private String clientId;
    @com.fasterxml.jackson.annotation.JsonProperty("last_login_time")
    private LocalDateTime lastLoginTime;
    @com.fasterxml.jackson.annotation.JsonProperty("login_ip")
    private String loginIp;
}
