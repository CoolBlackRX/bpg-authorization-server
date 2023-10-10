package com.bpg.authorization.server.support;

import com.bpg.common.kit.MyResultCode;
import lombok.Data;

/**
 * 登陆结果
 *
 * @author yangp
 * @since 2019-07-22
 */
@Data
public class RespBean {

    private String message;
    private Integer code;
    private String token;
    private String refreshToken;
    private Boolean success;
    private Object data;

    private RespBean() {
    }

    private RespBean(MyResultCode myResultCode) {
        this.code = myResultCode.getCode();
        this.message = myResultCode.getMsg();
        this.success = myResultCode.getSuccess();
    }

    public static RespBean success(SuccessCode code, Object data) {
        RespBean respBean = new RespBean();
        respBean.setData(data);
        respBean.code = code.getCode();
        respBean.message = code.getMsg();
        respBean.success = code.getSuccess();
        return respBean;
    }

    public static RespBean success(SuccessCode code) {
        return success(code, null);
    }

    public static RespBean fail(ErrorCode code) {
        return new RespBean(code);
    }
}
