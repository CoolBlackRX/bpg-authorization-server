package com.bpg.authorization.server.configuration.handlers;

import com.bpg.authorization.server.support.RespBean;
import com.bpg.authorization.server.support.SuccessCode;
import com.bpg.authorization.server.util.ToolUtil;
import com.bpg.spring.boot.security.model.AgileUserDetail;
import com.google.common.collect.Sets;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.context.ProviderContext;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 该类当登陆成功时，在这里返回登陆成功的信息
 *
 * @author lou ke
 * @since 2020-09-03
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class LoginAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final OAuth2AuthorizationCodeRequestAuthenticationProvider oAuth2AuthorizationCodeRequestAuthenticationProvider;
    private final OAuth2AuthorizationCodeAuthenticationProvider oAuth2AuthorizationCodeAuthenticationProvider;
    private final RegisteredClientRepository registeredClientRepository;
    private final ProviderSettings providerSettings;


    @Override
    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication auth) {
        resp.setContentType("application/json;charset=utf-8");
        // 获取当前登陆用户信息
        AgileUserDetail user = (AgileUserDetail) auth.getPrincipal();
        AgileUserDetail agileUserDetail = new AgileUserDetail();
        // 返回给前端的对象，移除密码、权限、角色等敏感信息
        BeanUtils.copyProperties(user, agileUserDetail);
        agileUserDetail.setPassword(null);
        agileUserDetail.setAuthorities(null);
        agileUserDetail.setIsLocked(null);
        agileUserDetail.setEnableEnd(null);
        agileUserDetail.setIsEnable(null);
        agileUserDetail.setInterfaceAuthCodeList(null);
        RespBean success = RespBean.success(SuccessCode.LOGIN_SUCCESS, agileUserDetail);
        log.info("用户：{} 登录", agileUserDetail.getEmployeeName());

        RegisteredClient registeredClient = registeredClientRepository.findByClientId("micro-client");
        Assert.notNull(registeredClient, "非法ClientId");

        OAuth2AuthorizationCodeRequestAuthenticationToken.Builder builder =
                OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), auth);
        // 不需要授权,直接通过
        builder.consent(false);
        builder.scopes(Sets.newHashSet("all"));
        // 授权码重定向地址
        builder.redirectUri("http://testagile.bpgroup.com.cn");
        builder.authorizationUri("http://testagile.bpgroup.com.cn");
        OAuth2AuthorizationCodeRequestAuthenticationToken oAuth2AuthorizationCodeRequestAuthenticationToken = builder.build();
        ProviderContextHolder.setProviderContext(new ProviderContext(providerSettings, null));
        // 授权码
        Authentication authenticate = oAuth2AuthorizationCodeRequestAuthenticationProvider.authenticate(oAuth2AuthorizationCodeRequestAuthenticationToken);
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationToken = (OAuth2AuthorizationCodeRequestAuthenticationToken) authenticate;
        OAuth2AuthorizationCode authorizationCode = authorizationCodeRequestAuthenticationToken.getAuthorizationCode();
        // 根据授权码获取 token 和 refresh_token
        OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken =
                new OAuth2ClientAuthenticationToken(registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_POST, registeredClient.getClientSecret());
        Assert.notNull(authorizationCode, "生成授权码为空");
        OAuth2AuthorizationCodeAuthenticationToken oAuth2AuthorizationCodeAuthenticationToken =
                new OAuth2AuthorizationCodeAuthenticationToken(authorizationCode.getTokenValue(), oAuth2ClientAuthenticationToken,
                        oAuth2AuthorizationCodeRequestAuthenticationToken.getRedirectUri(), null);
        Authentication tokenAuthentication = oAuth2AuthorizationCodeAuthenticationProvider.authenticate(oAuth2AuthorizationCodeAuthenticationToken);
        OAuth2AccessTokenAuthenticationToken oAuth2AccessTokenAuthenticationToken = (OAuth2AccessTokenAuthenticationToken) tokenAuthentication;
        OAuth2AccessToken accessToken = oAuth2AccessTokenAuthenticationToken.getAccessToken();
        success.setToken(accessToken.getTokenValue());
        OAuth2RefreshToken refreshToken = oAuth2AccessTokenAuthenticationToken.getRefreshToken();
        Assert.notNull(refreshToken, "refresh_token生成失败");
        success.setRefreshToken(refreshToken.getTokenValue());
        ToolUtil.respBean(resp, success);
    }
}
