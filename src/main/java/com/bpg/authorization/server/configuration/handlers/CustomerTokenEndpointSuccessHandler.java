package com.bpg.authorization.server.configuration.handlers;

import com.bpg.spring.boot.security.entity.Md5TokenHolder;
import com.bpg.spring.boot.security.entity.TokenContainer;
import com.bpg.spring.boot.security.entity.TokenHolder;
import com.bpg.spring.boot.security.store.CustomerTokenStore;
import lombok.RequiredArgsConstructor;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Map;

/**
 * @author zhaohq
 * create time: 2023/10/12 10:21:12
 */
@RequiredArgsConstructor
public class CustomerTokenEndpointSuccessHandler implements AuthenticationSuccessHandler {
    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
            new OAuth2AccessTokenResponseHttpMessageConverter();
    private final AuthenticationConverter authenticationConverter = new DelegatingAuthenticationConverter(
            Arrays.asList(new OAuth2AuthorizationCodeAuthenticationConverter(),
                    new OAuth2RefreshTokenAuthenticationConverter(),
                    new OAuth2ClientCredentialsAuthenticationConverter()));
    private final CustomerTokenStore customerTokenStore;
    private final CustomerMd5TokenConverter customerMd5TokenConverter;
    private final OAuth2AuthorizationService oAuth2AuthorizationService;

    /**
     * 此处只简单借用 OAuth2TokenEndpointFilter 内的 successHandler,在之前把 jwt token 转换成 md5 token
     */


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        // token 转成 md5 token, 并移除过期的 token 和 refresh_token , refresh_token reuse = false
        Authentication readAuthentication = authenticationConverter.convert(request);
        if (readAuthentication instanceof OAuth2RefreshTokenAuthenticationToken) {
            OAuth2RefreshTokenAuthenticationToken oAuth2RefreshTokenAuthenticationToken = (OAuth2RefreshTokenAuthenticationToken) readAuthentication;
            String refreshToken = oAuth2RefreshTokenAuthenticationToken.getRefreshToken();
            TokenHolder jwtToken = TokenHolder.of(null, refreshToken);
            TokenContainer tokenContainer = customerTokenStore.findByJwtToken(jwtToken);
            customerTokenStore.remove(tokenContainer);
        }
        // 以下代码参照 OAuth2TokenEndpointFilter#sendAccessTokenResponse
        OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
                (OAuth2AccessTokenAuthenticationToken) authentication;
        OAuth2AccessToken accessToken = accessTokenAuthentication.getAccessToken();
        OAuth2RefreshToken refreshToken = accessTokenAuthentication.getRefreshToken();
        Map<String, Object> additionalParameters = accessTokenAuthentication.getAdditionalParameters();

        // md5 处理 jwt token
        RegisteredClient registeredClient = accessTokenAuthentication.getRegisteredClient();
        Assert.notNull(refreshToken, "refreshToken 为空");
        Md5TokenHolder md5TokenHolder = customerMd5TokenConverter.apply(registeredClient, TokenHolder.of(accessToken.getTokenValue(), refreshToken.getTokenValue()));

        OAuth2AccessTokenResponse.Builder builder =
                OAuth2AccessTokenResponse.withToken(md5TokenHolder.getAccessToken())
                        .tokenType(accessToken.getTokenType())
                        .scopes(accessToken.getScopes());
        if (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null) {
            builder.expiresIn(ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()));
        }
        builder.refreshToken(md5TokenHolder.getRefreshToken());
        if (!CollectionUtils.isEmpty(additionalParameters)) {
            builder.additionalParameters(additionalParameters);
        }
        OAuth2AccessTokenResponse accessTokenResponse = builder.build();
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        this.accessTokenHttpResponseConverter.write(accessTokenResponse, null, httpResponse);
    }
}
