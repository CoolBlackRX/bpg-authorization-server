package com.bpg.authorization.server.configuration.model;

import lombok.Data;

import java.io.Serializable;

/**
 * 登录用户存储对象
 *
 * @author zhaohq
 */
@Data
public class AuthenticationBean implements Serializable {
    private String username;
    private String password;
}
