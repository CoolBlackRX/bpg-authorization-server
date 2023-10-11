package com.bpg.authorization.server.configuration.handlers;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * 该类当登出成功时，在这里返回登出成功的信息
 *
 * @author yangp
 * @since 2019-07-22
 */

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomerLogoutHandler implements LogoutHandler {

    private final BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
    private final OAuth2AuthorizationService oAuth2AuthorizationService;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String token = bearerTokenResolver.resolve(request);
        Assert.notNull(token, "信息错误");

        OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        // 可能手动直接删除数据库内的token,不影响用户退出
        if (oAuth2Authorization == null) {
            return;
        }
        oAuth2AuthorizationService.remove(oAuth2Authorization);
        log.info("用户：{} 退出系统", oAuth2Authorization.getPrincipalName());
    }
}
