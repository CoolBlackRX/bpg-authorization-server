package com.bpg.authorization.server.support;

import com.bpg.common.kit.MyResultCode;

public enum ErrorCode implements MyResultCode {

    NOT_LOGIN(50006, "未登陆，请先登陆!"),
    NO_USER_EXIST(500, "用户名或密码错误"),
    LOGIN_FAIL(500, "登陆失败"),
    NOT_MATCH(500, "账户名或者密码输入错误!"),
    ACCOUNT_ISLOCKED(500, "账户被锁定，请联系管理员!"),
    PASSWORD_EXPIRED(500, "密码过期，请联系管理员!"),
    ACCOUNT_EXPIRED(500, "账户过期，请联系管理员!"),
    ACCOUNT_DISABLE(500, "账户被禁用，请联系管理员!"),
    PERMISSION_DENIED(403, "权限不足，请联系管理员!"),
    ;

    private final Integer code;
    private final String msg;

    ErrorCode(Integer code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    @Override
    public Integer getCode() {
        return code;
    }

    @Override
    public String getMsg() {
        return msg;
    }

    @Override
    public Boolean getSuccess() {
        return false;
    }
}
