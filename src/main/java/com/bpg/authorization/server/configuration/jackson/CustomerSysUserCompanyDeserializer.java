package com.bpg.authorization.server.configuration.jackson;

import com.bpg.spring.boot.security.model.SysSystem;
import com.bpg.spring.boot.security.model.SysUserCompany;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

/**
 * @author zhaohq
 * create time: 2023/10/12 19:21:59
 */
public class CustomerSysUserCompanyDeserializer extends JsonDeserializer<SysUserCompany> {
    @Override
    public SysUserCompany deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JacksonException {
        ObjectMapper mapper = (ObjectMapper) jsonParser.getCodec();
        JsonNode jsonNode = mapper.readTree(jsonParser);

        Integer companyId = JacksonJsonNodeReader.readJsonNode(jsonNode, "companyId").asInt();
        String companyCode = JacksonJsonNodeReader.readJsonNode(jsonNode, "companyCode").asText();
        String companyName = JacksonJsonNodeReader.readJsonNode(jsonNode, "companyName").asText();
        String isDefault = JacksonJsonNodeReader.readJsonNode(jsonNode, "isDefault").asText();

        SysUserCompany sysUserCompany = new SysUserCompany();
        sysUserCompany.setCompanyId(companyId);
        sysUserCompany.setCompanyCode(companyCode);
        sysUserCompany.setCompanyName(companyName);
        sysUserCompany.setIsDefault(isDefault);
        return sysUserCompany;
    }
}
