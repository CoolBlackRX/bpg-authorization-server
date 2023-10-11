package com.bpg.authorization.server.configuration.providers;

import cn.hutool.core.util.BooleanUtil;
import com.bpg.authorization.server.configuration.nacos.BpgLdapAuthProperties;
import com.bpg.authorization.server.feign.SystemFeign;
import com.bpg.common.kit.ApiResult;
import com.bpg.spring.boot.security.model.AgileUserDetail;
import com.google.common.base.Splitter;
import com.google.common.collect.Sets;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import util.AESUtil;

import java.util.Set;


/**
 * @author zhaohq
 * create time: 2023/10/11 13:33:33
 */
@Slf4j
@RequiredArgsConstructor
public class CompositeCustomerAuthenticationProvider extends DaoAuthenticationProvider {
    private final SystemFeign systemFeign;
    private final BpgLdapAuthProperties bpgLdapAuthProperties;

    public Set<String> getIgnoreLdapAuthUsers() {
        try {
            return Sets.newHashSet(Splitter.on(",").split(bpgLdapAuthProperties.getIgnoreUserNames()));
        } catch (Exception e) {
            log.error("解析忽略用户ldap认证登录异常：{}", bpgLdapAuthProperties.getIgnoreUserNames());
            return Sets.newHashSet();
        }
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        if (authentication.getCredentials() == null) {
            logger.debug("Authentication failed: no credentials provided");

            throw new BadCredentialsException(messages.getMessage(
                    "AbstractUserDetailsAuthenticationProvider.badCredentials",
                    "Bad credentials"));
        }
        AgileUserDetail agileUserDetail = (AgileUserDetail) userDetails;
        agileUserDetail.setPassword("{bcrypt}" + agileUserDetail.getPassword());
        String presentedPassword = authentication.getCredentials().toString();
        if (BooleanUtil.toBoolean(bpgLdapAuthProperties.getEnableLdap())) {
            if (!getIgnoreLdapAuthUsers().contains(authentication.getPrincipal().toString().trim())) {
                ApiResult<Boolean> ldapResult = systemFeign.checkLdapUserPassword(authentication.getPrincipal().toString().trim(), presentedPassword);
                if (ApiResult.success().code.equals(ldapResult.getCode()) && BooleanUtil.isTrue(ldapResult.getData())) {
                    return;
                }
                throw new UsernameNotFoundException("用户名或密码输入错误");
            }
        }
        String password = AESUtil.decryptFormPassword(presentedPassword);
        if (!getPasswordEncoder().matches(password, userDetails.getPassword())) {
            logger.debug("Authentication failed: password does not match stored value");

            throw new BadCredentialsException(messages.getMessage(
                    "AbstractUserDetailsAuthenticationProvider.badCredentials",
                    "Bad credentials"));
        }
    }
}
