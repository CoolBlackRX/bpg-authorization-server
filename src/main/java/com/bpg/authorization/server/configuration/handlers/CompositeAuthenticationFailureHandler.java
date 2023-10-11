package com.bpg.authorization.server.configuration.handlers;

import com.bpg.authorization.server.configuration.filters.UserAuthenticationFilter;
import com.bpg.authorization.server.configuration.model.AuthenticationBean;
import com.bpg.authorization.server.configuration.oauth2.Oauth2ClientLoginConfiguration;
import com.bpg.authorization.server.support.RespBean;
import com.bpg.authorization.server.util.ToolUtil;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Optional;
import java.util.function.Function;

/**
 * @author zhaohq
 * @date 2022/11/3
 **/
@Component
public class CompositeAuthenticationFailureHandler implements AuthenticationFailureHandler {
    private final AuthenticationFailureHandler jsonAuthenticationFailureHandler = (request, response, exception) -> {
        response.setContentType("application/json;charset=utf-8");
        RespBean respBean = LoginHandlerUtil.loginExceptionHandle(exception);
        ToolUtil.respBean(response, respBean);
    };

    private final AuthenticationFailureHandler simpleUrlAuthenticationFailureHandler =
            new CustomerAuthenticationFailureHandler("/login");


    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String clientId = LoginHandlerUtil.getClientId(request, response);
        Assert.notNull(clientId, "client_id is empty");
        Oauth2ClientLoginConfiguration.ClientAttribute clientAttribute = LoginHandlerUtil.findClientAttribute(clientId);

        AuthenticationFailureHandler authenticationFailureHandler = Optional.of(clientId).map(e -> {
            if (LoginHandlerUtil.AUTHORIZATION_CODE.equals(clientAttribute.getMethod())) {
                return simpleUrlAuthenticationFailureHandler;
            }
            if (LoginHandlerUtil.PASSWORD.equals(clientAttribute.getMethod())) {
                return jsonAuthenticationFailureHandler;
            }
            return null;
        }).orElse(simpleUrlAuthenticationFailureHandler);
        authenticationFailureHandler.onAuthenticationFailure(request, response, exception);
    }


    private static final Function<HttpServletRequest, AuthenticationBean> FUNCTION = request ->
            Optional.ofNullable(UserAuthenticationFilter.getBodyLoginParameters(request))
                    .orElseGet(() -> UserAuthenticationFilter.getLoginParameters(request));


    static class CustomerAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
        public CustomerAuthenticationFailureHandler(String defaultFailureUrl) {
            super(defaultFailureUrl);
        }

        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
            super.onAuthenticationFailure(request, response, exception);
            HttpSession session = request.getSession(false);
            if (session != null) {
                AuthenticationBean authenticationBean = FUNCTION.apply(request);
                request.getSession().setAttribute(LoginHandlerUtil.BAD_CREDENTIALS_VALUE, authenticationBean);
            }
        }
    }
}
