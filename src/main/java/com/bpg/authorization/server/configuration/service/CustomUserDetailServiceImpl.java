package com.bpg.authorization.server.configuration.service;

import com.bpg.authorization.server.feign.SystemFeign;
import com.bpg.common.kit.ApiResult;
import com.bpg.spring.boot.security.model.AgileUserDetail;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

/**
 * 自定义UserDetailService，用户信息来自 system-management微服务中
 *
 * @author lou ke
 * @since 2020/8/14 15:43
 */
@Slf4j
@Service(value = "userDetailsService")
public class CustomUserDetailServiceImpl implements UserDetailsService {

    @Resource
    SystemFeign systemFeign;

    /**
     * 重写loadUserByUsername方法
     *
     * @param username 用户名
     * @return UserDetails
     * @throws UsernameNotFoundException 用户不存在异常
     */
    @Override
    public AgileUserDetail loadUserByUsername(String username) throws UsernameNotFoundException {
        ApiResult<AgileUserDetail> agileUserDetailApiResult = systemFeign.loadUserByUserName(username);
        if (Boolean.TRUE.equals(agileUserDetailApiResult.getSuccess())) {
            AgileUserDetail agileUserDetail = agileUserDetailApiResult.getData();
            log.info("当前登录用户：{},根据用户名获取的用户信息:{}", username, agileUserDetail.getEmployeeName());
            return agileUserDetail;
        }
        return null;
    }

    public AgileUserDetail loadUserByUsername(String username, String platform) {
        // 如果将用户登录设备信息传到sys,将该参数加进去
        AgileUserDetail sysUserDto = loadUserByUsername(username);
        sysUserDto.setPlatform(platform);
        return sysUserDto;
    }


}
