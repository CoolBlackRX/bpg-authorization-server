package com.bpg.authorization.server.configuration.handlers;

import cn.hutool.core.collection.CollUtil;
import com.bpg.authorization.server.configuration.oauth2.Oauth2ClientLoginConfiguration;
import com.bpg.authorization.server.support.ErrorCode;
import com.bpg.authorization.server.support.RespBean;
import com.bpg.common.exception.BizException;
import com.bpg.spring.boot.constant.GlobalConstant;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * @author zhaohq
 * @date 2022/11/3
 **/
@Component
public class LoginHandlerUtil implements ApplicationContextAware {
    private static final RequestCache REQUEST_CACHE = new HttpSessionRequestCache();
    private static ApplicationContext context;

    /**
     * 重定向到认证成功页面
     */
    public static final String AUTHORIZATION_CODE = "redirect";
    /**
     * 返回登录成功的json数据
     */
    public static final String PASSWORD = "json";
    public static final String BAD_CREDENTIALS_VALUE = "BadCredentialsExceptionValue";

    @Override
    public void setApplicationContext(@NonNull ApplicationContext applicationContext) throws BeansException {
        setContext(applicationContext);
    }

    public static void setContext(ApplicationContext context) {
        LoginHandlerUtil.context = context;
    }

    public static Oauth2ClientLoginConfiguration.ClientAttribute findClientAttribute(String clientId) {
        List<Oauth2ClientLoginConfiguration.ClientAttribute> clients = Optional.of(getOauth2ClientConfiguration())
                .map(Oauth2ClientLoginConfiguration::getClients).orElseGet(Collections::emptyList);
        return clients.stream().filter(e -> e.getName().equals(clientId)).findFirst()
                .orElseThrow(() -> new BizException("未配置登录授权方式"));
    }

    public static Oauth2ClientLoginConfiguration getOauth2ClientConfiguration() {
        return context.getBean(Oauth2ClientLoginConfiguration.class);
    }

    public static String getClientId(HttpServletRequest request, HttpServletResponse response) {
        String clientId = request.getHeader(GlobalConstant.CLIENT_ID.getValue());
        if (clientId == null) {
            SavedRequest savedRequest = REQUEST_CACHE.getRequest(request, response);
            if (savedRequest != null) {
                List<String> clientIdList = CollUtil.toList(savedRequest.getParameterValues("client_id"));
                if (CollUtil.isNotEmpty(clientIdList)) {
                    return clientIdList.get(0);
                }
            }
        }
        return clientId;
    }

    public static RespBean loginExceptionHandle(AuthenticationException exception) {
        RespBean error;
        if (exception instanceof InternalAuthenticationServiceException) {
            error = RespBean.fail(ErrorCode.NO_USER_EXIST);
        } else if (exception instanceof BadCredentialsException) {
            error = RespBean.fail(ErrorCode.NOT_MATCH);
        } else if (exception instanceof LockedException) {
            error = RespBean.fail(ErrorCode.ACCOUNT_ISLOCKED);
        } else if (exception instanceof CredentialsExpiredException) {
            error = RespBean.fail(ErrorCode.PASSWORD_EXPIRED);
        } else if (exception instanceof AccountExpiredException) {
            error = RespBean.fail(ErrorCode.ACCOUNT_EXPIRED);
        } else if (exception instanceof DisabledException) {
            error = RespBean.fail(ErrorCode.ACCOUNT_DISABLE);
        } else if (exception instanceof UsernameNotFoundException) {
            error = RespBean.fail(ErrorCode.NO_USER_EXIST);
        } else {
            error = RespBean.fail(ErrorCode.LOGIN_FAIL);
        }
        return error;
    }
}
