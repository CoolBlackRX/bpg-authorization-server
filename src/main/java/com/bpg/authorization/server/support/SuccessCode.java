package com.bpg.authorization.server.support;

import com.bpg.common.kit.MyResultCode;

/**
 * @author BPGlouk
 * @since 2021/03/11 15:40
 */

public enum SuccessCode implements MyResultCode {

    LOGIN_SUCCESS(20000, "登陆成功"),
    LOGOUT_SUCCESS(20000, "注销成功"),
    ;

    private final Integer code;
    private final String msg;

    SuccessCode(Integer code, String msg) {
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
        return true;
    }
}
