package com.bpg.authorization.server.configuration;

import com.bpg.authorization.server.configuration.jackson.*;
import com.bpg.authorization.server.configuration.jwk.Jwks;
import com.bpg.spring.boot.security.model.*;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.time.Duration;
import java.util.List;

/**
 * @author zhaohq
 * @date 2023/9/5
 **/
@Configuration
@RequiredArgsConstructor
public class TokenConfiguration {
    private final JdbcTemplate jdbcTemplate;


    /**
     * 注册客户端应用
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId("be0a8523-c8c1-4643-8a9e-5efb67e83ce0")
                .clientId("micro-client")
                // 密码 123
                .clientSecret("{bcrypt}$2a$10$PfqZRh.tJxyXo0ddtg28UOVgxhemvrgJlZIYpChNjYLkBQZpH0nty")
                .clientAuthenticationMethods(s -> {
                    s.add(ClientAuthenticationMethod.CLIENT_SECRET_POST);
                    s.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                })
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .redirectUri("http://testagile.bpgroup.com.cn")
                .scope("all")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                        .accessTokenTimeToLive(Duration.ofDays(1L))
                        .refreshTokenTimeToLive(Duration.ofDays(30L))
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        // refresh_token 不复用
                        .reuseRefreshTokens(false)
                        .build())
                .build();

        RegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        registeredClientRepository.save(registeredClient);
        return registeredClientRepository;
    }

    /**
     * 持久化授权生成的token，后续可放到 redis
     */
    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService(RegisteredClientRepository registeredClientRepository) {
        JdbcOAuth2AuthorizationService oAuth2AuthorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
        JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper authorizationRowMapper = new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(
                registeredClientRepository);
        authorizationRowMapper.setLobHandler(new DefaultLobHandler());

        ObjectMapper objectMapper = new ObjectMapper();
        ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        objectMapper.registerModules(securityModules);
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        objectMapper.addMixIn(SysSystem.class, SysSystemMixin.class);
        objectMapper.addMixIn(SysRole.class, SysRoleMixin.class);
        objectMapper.addMixIn(SysUserCompany.class, SysUserCompanyMixin.class);
        objectMapper.addMixIn(UserCompanyContainer.Organization.class, UserCompanyContainerOrganizationMixin.class);
        objectMapper.addMixIn(UserCompanyContainer.WorkShop.class, UserCompanyContainerWorkShopMixin.class);
        authorizationRowMapper.setObjectMapper(objectMapper);

        oAuth2AuthorizationService.setAuthorizationRowMapper(authorizationRowMapper);
        return oAuth2AuthorizationService;

    }

    /**
     * 持久化客户端应用授权记录
     */
    @Bean
    public OAuth2AuthorizationConsentService oAuth2AuthorizationConsentService(RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 默认发放令牌
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }


    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = context.getPrincipal();
            AgileUserDetail agileUserDetail = (AgileUserDetail) usernamePasswordAuthenticationToken.getPrincipal();
            JwtClaimsSet.Builder claims = context.getClaims();
            claims.claim("userId", agileUserDetail.getUserId());
            claims.claim("userName", agileUserDetail.getUserName());
            claims.claim("employeeId", "");
            claims.claim("employeeCode", agileUserDetail.getEmployeeCode());
            claims.claim("hasAdminRole", agileUserDetail.isHasAdminRole());
            claims.claim("hasSuperAdminRole", agileUserDetail.isHasSuperAdminRole());
            claims.claim("deptId", agileUserDetail.getDeptId());
            claims.claim("currentDeptId", agileUserDetail.getCurrentDeptId());
            claims.claim("erpBusinessEntityId", agileUserDetail.getErpBusinessEntityId());
            claims.claim("departmentId", agileUserDetail.getDepartmentId());
            claims.claim("erpDeptSeg", agileUserDetail.getErpDeptSeg());
        };
    }


    @Bean
    public OAuth2TokenGenerator<? extends OAuth2Token> oAuth2TokenGenerator(JwtEncoder jwtEncoder,
                                                                            OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer) {
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        // jwt token放前面
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        // token 增强
        jwtGenerator.setJwtCustomizer(tokenCustomizer);
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    /**
     * 魔法改造开始
     * 由于前后端分离，登录页面在前端，登录验证使用 DaoAuthenticationProvider,在登陆成功后手动mock构造一个
     * OAuth2AuthorizationCodeRequestAuthenticationProvider 生成的认证码 code，并根据这个认证码返回 token 和 refresh_token
     */
    @Bean
    public OAuth2AuthorizationCodeRequestAuthenticationProvider oAuth2AuthorizationCodeRequestAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
                                                                                                                     OAuth2AuthorizationService authorizationService,
                                                                                                                     OAuth2AuthorizationConsentService authorizationConsentService) {
        // 生成授权码
        return new OAuth2AuthorizationCodeRequestAuthenticationProvider(registeredClientRepository, authorizationService, authorizationConsentService);
    }

    @Bean
    public OAuth2AuthorizationCodeAuthenticationProvider oAuth2AuthorizationCodeAuthenticationProvider(OAuth2AuthorizationService oAuth2AuthorizationService, OAuth2TokenGenerator<? extends OAuth2Token> oAuth2TokenGenerator) {
        // 根据授权码生成token 和 refresh_token
        return new OAuth2AuthorizationCodeAuthenticationProvider(oAuth2AuthorizationService, oAuth2TokenGenerator);
    }


    @Bean
    public OAuth2RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider(OAuth2AuthorizationService oAuth2AuthorizationService,
                                                                                       OAuth2TokenGenerator<? extends OAuth2Token> oAuth2TokenGenerator) {
        //  刷新 token 和 refresh_token
        return new OAuth2RefreshTokenAuthenticationProvider(oAuth2AuthorizationService, oAuth2TokenGenerator);
    }

    @Bean
    public OAuth2ClientCredentialsAuthenticationProvider clientCredentialsAuthenticationProvider(OAuth2AuthorizationService oAuth2AuthorizationService,
                                                                                                 OAuth2TokenGenerator<? extends OAuth2Token> oAuth2TokenGenerator) {
        return new OAuth2ClientCredentialsAuthenticationProvider(oAuth2AuthorizationService, oAuth2TokenGenerator);
    }

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
                .issuer("http://10.10.52.90:9001")
                .build();
    }

}
