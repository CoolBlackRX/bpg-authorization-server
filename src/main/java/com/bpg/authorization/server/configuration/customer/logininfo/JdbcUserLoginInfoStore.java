package com.bpg.authorization.server.configuration.customer.logininfo;

import com.bpg.authorization.server.configuration.customer.UserLoginInfoStore;
import com.bpg.spring.boot.security.model.AgileUserDetail;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import util.IpUtil;

import javax.servlet.http.HttpServletRequest;
import java.sql.Timestamp;
import java.time.LocalDateTime;

/**
 * @author zhaohq
 * @date 2022/12/2
 **/
@Component
public class JdbcUserLoginInfoStore implements UserLoginInfoStore {


    private static final String INSERT = "INSERT INTO `oauth_user_login_info`(`USER_ID`, `EMPLOYEE_NAME`, `CLIENT_ID`, `LAST_LOGIN_TIME`," +
            " `LOGIN_IP`) " +
            "VALUES (?, ?, ?, ?, ?);";

    private JdbcTemplate jdbcTemplate;

    @Autowired
    public void setJdbcTemplate(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void storeLoginInfo(HttpServletRequest httpServletRequest, @NonNull String clientId, AgileUserDetail agileUserDetail) {

        String ip = IpUtil.getRequestRealIp(httpServletRequest);

        jdbcTemplate.update(INSERT, ps -> {
            ps.setInt(1, agileUserDetail.getUserId());
            ps.setString(2, agileUserDetail.getEmployeeName());
            ps.setString(3, clientId);
            ps.setTimestamp(4, Timestamp.valueOf(LocalDateTime.now()));
            ps.setString(5, ip);
        });

    }
}
