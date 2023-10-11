package com.bpg.authorization.server.configuration.nacos;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.stereotype.Repository;

/**
 * @author zhaohq
 * @date 2022/6/9
 **/
@Repository
@RefreshScope
public class BpgLdapAuthProperties {
    @Value("${enableLdap:false}")
    private String enableLdap;

    @Value("${ignoreUserNames:admin}")
    private String ignoreUserNames;


    public String getIgnoreUserNames() {
        return ignoreUserNames;
    }

    public void setIgnoreUserNames(String ignoreUserNames) {
        this.ignoreUserNames = ignoreUserNames;
    }

    public String getEnableLdap() {
        return enableLdap;
    }

    public void setEnableLdap(String enableLdap) {
        this.enableLdap = enableLdap;
    }
}
