package com.bpg.authorization.server.feign;

import com.bpg.cloud.spring.configuration.FeignConfiguration;
import com.bpg.common.kit.ApiResult;
import com.bpg.spring.boot.security.model.AgileUserDetail;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @author lou ke
 * @since 2020/8/14 15:15
 */
@FeignClient(value = "system-management", configuration = FeignConfiguration.class, fallbackFactory = SystemFeignFallback.class)
public interface SystemFeign {


    /**
     * feign调用 system-management微服务上的接口获取用户信息
     *
     * @param username 用户名
     * @return 用户信息
     */
    @GetMapping(value = "/api/sys/system/open/user/loadUserByUserName")
    ApiResult<AgileUserDetail> loadUserByUserName(@RequestParam("username") String username);


    /**
     * ldap 验证密码登录
     *
     * @param username 用户名
     * @param password 密码
     * @return ApiResult<Boolean>
     */
    @GetMapping(value = "/api/sys/system/open/ldap/checkUser")
    ApiResult<Boolean> checkLdapUserPassword(@RequestParam("username") String username, @RequestParam("password") String password);

}
