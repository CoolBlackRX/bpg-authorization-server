package com.bpg.authorization.server.configuration;

import cn.hutool.extra.spring.SpringUtil;
import com.bpg.authorization.server.configuration.filters.UserAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

/**
 * @author zhaohq
 * @date 2023/9/1
 **/
@Configuration
@EnableWebSecurity(debug = true)
@RequiredArgsConstructor
@Import(SpringUtil.class)
public class AuthorizationServerConfiguration {
    private final AuthenticationSuccessHandler authenticationSuccessHandler;

    @Bean
    public SecurityFilterChain httpSecurityFilterChain(HttpSecurity httpSecurity,
                                                       // 身份验证
                                                       List<AuthenticationProvider> providers) throws Exception {
        // 认证服务器配置,前后端分离，登陆页面在前端，没办法做授权登录重定向
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<>();
        httpSecurity.apply(authorizationServerConfigurer);
        // 关闭 session
        httpSecurity.sessionManagement().disable();
        // 关闭 csrf
        httpSecurity.csrf().disable();
        // 登录
        httpSecurity.formLogin()
                .loginPage("/login")
                .successHandler(authenticationSuccessHandler)
        ;
        // 注册登录过滤器，支持json参数登录
        httpSecurity.addFilterAt(new UserAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        // 登录认证
        // 账号密码
        AuthenticationManagerBuilder authenticationManagerBuilder = httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);
        for (AuthenticationProvider provider : providers) {
            authenticationManagerBuilder.authenticationProvider(provider);
        }

        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * 用户账号密码解析
     * 后续支持 ldap 认证，但是返回的是 agile 平台的用户信息
     * 尝试添加 LdapAuthenticationProvider
     * 注意： ProviderManager 验证时 单个 provider 验证通过就不再处理后续的 provider, 注意验证优先级
     *
     * @param userDetailsService 用户信息获取类
     * @return DaoAuthenticationProvider
     */
    @Bean
    public DaoAuthenticationProvider customerLoginAuthProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        return daoAuthenticationProvider;
    }


}
