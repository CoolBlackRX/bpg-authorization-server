package com.bpg.authorization.server.configuration.handlers;

import cn.hutool.http.Header;
import com.bpg.authorization.server.configuration.oauth2.Oauth2ClientLoginConfiguration;
import com.bpg.authorization.server.support.RespBean;
import com.bpg.authorization.server.support.SuccessCode;
import com.bpg.authorization.server.util.ToolUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

/**
 * @author zhaohq
 * @date 2022/11/3
 **/
@Component
public class CompositeLogoutSuccessHandler implements LogoutSuccessHandler {
    private final LogoutSuccessHandler jsonLogoutSuccessHandler = (request, response, authentication) -> {
        response.setContentType("application/json;charset=utf-8");
        RespBean success = RespBean.success(SuccessCode.LOGOUT_SUCCESS);
        ToolUtil.respBean(response, success);
    };
    private final LogoutSuccessHandler simpleUrlLogoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String clientId = LoginHandlerUtil.getClientId(request, response);
        Assert.notNull(clientId, "clientId参数丢失");

        LogoutSuccessHandler logoutSuccessHandler = Optional.of(clientId).map(e -> {
            Oauth2ClientLoginConfiguration.ClientAttribute clientAttribute = LoginHandlerUtil.findClientAttribute(clientId);
            if (LoginHandlerUtil.AUTHORIZATION_CODE.equals(clientAttribute.getMethod())) {
                return simpleUrlLogoutSuccessHandler;
            }
            if (LoginHandlerUtil.PASSWORD.equals(clientAttribute.getMethod())) {
                return jsonLogoutSuccessHandler;
            }
            return null;
        }).orElse(simpleUrlLogoutSuccessHandler);
        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
    }
}
