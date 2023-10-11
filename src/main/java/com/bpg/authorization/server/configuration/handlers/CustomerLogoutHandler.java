package com.bpg.authorization.server.configuration.handlers;


import cn.hutool.core.util.ObjectUtil;
import com.bpg.common.exception.BizException;
import com.bpg.spring.boot.constant.GlobalConstant;
import com.bpg.spring.boot.security.entity.Md5TokenHolder;
import com.bpg.spring.boot.security.entity.TokenHolder;
import com.bpg.spring.boot.security.store.CustomerTokenStore;
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
public class CustomerLogoutHandler implements LogoutHandler {

    private final DefaultBearerTokenResolver bearerAccessTokenResolver = new DefaultBearerTokenResolver();
    private final DefaultBearerTokenResolver bearerRefreshTokenResolver = new DefaultBearerTokenResolver();

    private final OAuth2AuthorizationService oAuth2AuthorizationService;
    private final CustomerTokenStore customerTokenStore;

    public CustomerLogoutHandler(CustomerTokenStore customerTokenStore, OAuth2AuthorizationService oAuth2AuthorizationService) {
        this.customerTokenStore = customerTokenStore;
        this.oAuth2AuthorizationService = oAuth2AuthorizationService;
        bearerRefreshTokenResolver.setBearerTokenHeaderName(GlobalConstant.REFRESH_TOKEN.getValue());
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String accessToken = bearerAccessTokenResolver.resolve(request);
        String refreshToken = bearerRefreshTokenResolver.resolve(request);
        if (ObjectUtil.hasEmpty(accessToken, refreshToken)) {
            throw new BizException("数据错误，推出失败");
        }

        Md5TokenHolder md5TokenHolder = Md5TokenHolder.of(accessToken, refreshToken);
        TokenHolder tokenHolder = customerTokenStore.find(md5TokenHolder);

        OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByToken(tokenHolder.getAccessToken(), OAuth2TokenType.ACCESS_TOKEN);
        // 可能手动直接删除数据库内的token,不影响用户退出
        if (oAuth2Authorization == null) {
            return;
        }
        oAuth2AuthorizationService.remove(oAuth2Authorization);
        customerTokenStore.remove(md5TokenHolder);
        log.info("用户：{} 退出系统", oAuth2Authorization.getPrincipalName());
    }
}
