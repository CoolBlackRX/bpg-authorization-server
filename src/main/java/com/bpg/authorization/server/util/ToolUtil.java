package com.bpg.authorization.server.util;

import com.bpg.authorization.server.support.RespBean;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import lombok.extern.slf4j.Slf4j;

import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

/**
 * @author lou ke
 * @since 2021-04-22
 */
@Slf4j
public class ToolUtil {

    private ToolUtil() {
    }

    private static final ObjectMapper OBJECT_MAPPER;

    static {
        OBJECT_MAPPER = new ObjectMapper();
        SimpleModule simpleModule = new SimpleModule();
        simpleModule.addSerializer(Long.TYPE, ToStringSerializer.instance);
        simpleModule.addSerializer(Long.class, ToStringSerializer.instance);
        OBJECT_MAPPER.registerModule(simpleModule);
        OBJECT_MAPPER.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    /**
     * 返回登陆结果
     *
     * @param response response
     * @param respBean respBean
     */
    public static void respBean(HttpServletResponse response, RespBean respBean) {
        try (PrintWriter out = response.getWriter()) {
            String resBody = OBJECT_MAPPER.writeValueAsString(respBean);
            out.print(resBody);
            out.flush();
        } catch (Exception e) {
            log.error("Exception:", e);
        }
    }
}
