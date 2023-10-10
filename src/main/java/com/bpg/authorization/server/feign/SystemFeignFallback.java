package com.bpg.authorization.server.feign;

import com.bpg.common.kit.ApiResult;
import com.bpg.spring.boot.security.model.AgileUserDetail;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.stereotype.Component;

/**
 * @author lou ke
 * @since 2020/8/14 15:16
 */
@Slf4j
@Component
public class SystemFeignFallback implements FallbackFactory<SystemFeign> {
    @Override
    public SystemFeign create(Throwable cause) {
        log.error("调用system-management服务接口出现异常", cause);
        return new SystemFeign() {
            @Override
            public ApiResult<AgileUserDetail> loadUserByUserName(String username) {
                return ApiResult.fail();
            }

            @Override
            public ApiResult<Boolean> checkLdapUserPassword(String username, String password) {
                return ApiResult.fail();
            }
        };
    }
}
