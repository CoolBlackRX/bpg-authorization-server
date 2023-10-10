package com.bpg.authorization.server.configuration.filters;


import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson.JSON;
import com.bpg.authorization.server.configuration.model.AuthenticationBean;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;

/**
 * 设置登陆参数为 JSON 格式的过滤器
 * <p>
 * 不继承 UsernamePasswordAuthenticationFilter 是因为后续很多Security的配置涉及到 AbstractAuthenticationProcessingFilter
 * 内的属性，否则要要在此 Filter 内手动设置 才会生效
 *
 * @author yangp
 * @see AbstractAuthenticationProcessingFilter
 * @since 2019-08-04
 */
@Slf4j
public class UserAuthenticationFilter implements Filter {
    private final RequestMatcher requiresAuthenticationRequestMatcher = new AntPathRequestMatcher("/login", "POST");

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (!requiresAuthenticationRequestMatcher.matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        AuthenticationBean bodyLoginParameters = getBodyLoginParameters(request);
        HttpServletRequestWrapper httpServletRequestWrapper = new HttpServletRequestWrapper(request) {
            @Override
            public String getParameter(String name) {

                if (UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY.equals(name) &&
                        StrUtil.isNotEmpty(bodyLoginParameters.getUsername())) {
                    return bodyLoginParameters.getUsername();
                }
                if (UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY.equals(name) &&
                        StrUtil.isNotEmpty(bodyLoginParameters.getPassword())) {
                    return bodyLoginParameters.getPassword();
                }

                return super.getParameter(name);
            }
        };
        chain.doFilter(httpServletRequestWrapper, response);
    }

    public static AuthenticationBean getBodyLoginParameters(HttpServletRequest request) {
        try (InputStream inputStream = request.getInputStream()) {
            AuthenticationBean authenticationBean = JSON.parseObject(inputStream, AuthenticationBean.class);
            return Optional.ofNullable(authenticationBean).orElseGet(AuthenticationBean::new);
        } catch (IOException exception) {
            return new AuthenticationBean();
        }
    }

    public static AuthenticationBean getLoginParameters(HttpServletRequest request) {
        AuthenticationBean authenticationBean = new AuthenticationBean();
        String username = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY;
        authenticationBean.setUsername(request.getParameter(username));
        String password = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY;
        authenticationBean.setPassword(request.getParameter(password));
        return authenticationBean;
    }
}
