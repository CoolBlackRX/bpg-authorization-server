package com.bpg.authorization.server.feign;

import com.bpg.common.kit.ApiResult;
import com.bpg.spring.boot.security.model.AgileUserDetail;
import org.springframework.stereotype.Component;

import java.util.Collections;

/**
 * @author zhaohq
 * @date 2023/9/4
 **/
@Component
public class MockSystemFeign implements SystemFeign {
    @Override
    public ApiResult<AgileUserDetail> loadUserByUserName(String username) {
        AgileUserDetail agileUserDetail = new AgileUserDetail();
        agileUserDetail.setUserId(95);
        agileUserDetail.setEmployeeName("赵汉青1111111");
        agileUserDetail.setUserName("zhaohq");
        agileUserDetail.setPassword("{bcrypt}$2a$10$PfqZRh.tJxyXo0ddtg28UOVgxhemvrgJlZIYpChNjYLkBQZpH0nty");
        agileUserDetail.setRoles(Collections.emptyList());

        agileUserDetail.setIsLocked("N");
        agileUserDetail.setIsEnable(1);
        agileUserDetail.setEnableEnd(null);

        return new ApiResult<>(agileUserDetail);
    }

    @Override
    public ApiResult<Boolean> checkLdapUserPassword(String username, String password) {
        return null;
    }
}
