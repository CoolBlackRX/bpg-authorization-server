package com.bpg.authorization.server.configuration.customer;

import com.bpg.spring.boot.security.model.AgileUserDetail;
import org.springframework.lang.NonNull;

import javax.servlet.http.HttpServletRequest;

/**
 * @author zhaohq
 * @date 2022/12/2
 **/
public interface UserLoginInfoStore {
    /**
     * 记录用户登录信息
     *
     * @param request         请求相应， 获取ip数据
     * @param clientId        应用id
     * @param agileUserDetail 用户信息
     */
    void storeLoginInfo(HttpServletRequest request, @NonNull String clientId, AgileUserDetail agileUserDetail);

}
