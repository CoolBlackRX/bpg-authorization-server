package com.bpg.authorization.server.configuration.handlers;

import cn.hutool.core.util.ObjectUtil;
import com.bpg.authorization.server.configuration.customer.UserLoginInfoStore;
import com.bpg.authorization.server.configuration.oauth2.Oauth2ClientLoginConfiguration;
import com.bpg.spring.boot.security.model.AgileUserDetail;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
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
@RequiredArgsConstructor
public class CompositeAuthenticationSuccessHandler implements AuthenticationSuccessHandler, InitializingBean {

    private AuthenticationSuccessHandler jsonAuthenticationSuccessHandler;
    private final SavedRequestAwareAuthenticationSuccessHandler savedRequestAwareAuthenticationSuccessHandler =
            new SavedRequestAwareAuthenticationSuccessHandler();

    private final UserLoginInfoStore userLoginInfoStore;

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(jsonAuthenticationSuccessHandler, "返回json格式用户登录数据");
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String clientId = LoginHandlerUtil.getClientId(request, response);
        AuthenticationSuccessHandler authenticationSuccessHandler = Optional.ofNullable(clientId).map(e -> {
            Oauth2ClientLoginConfiguration.ClientAttribute clientAttribute = LoginHandlerUtil.findClientAttribute(clientId);
            Assert.notNull(clientAttribute, "非法clientId");

            if (LoginHandlerUtil.AUTHORIZATION_CODE.equals(clientAttribute.getMethod())) {
                return savedRequestAwareAuthenticationSuccessHandler;
            }
            // password模式 返回 json 格式数据
            if (LoginHandlerUtil.PASSWORD.equals(clientAttribute.getMethod())) {
                return jsonAuthenticationSuccessHandler;
            }
            return null;
            // 默认重定向到主页
        }).orElse(savedRequestAwareAuthenticationSuccessHandler);
        authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);
        if (ObjectUtil.isNotNull(authentication)) {
            AgileUserDetail agileUserDetail = (AgileUserDetail) authentication.getPrincipal();
            Assert.notNull(clientId, "系统异常");
            userLoginInfoStore.storeLoginInfo(request, clientId, agileUserDetail);
        }
    }

    @Autowired
    public void setJsonAuthenticationSuccessHandler(AuthenticationSuccessHandler loginAuthenticationSuccessHandler) {
        this.jsonAuthenticationSuccessHandler = loginAuthenticationSuccessHandler;
    }

}
