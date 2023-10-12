package com.bpg.authorization.server.configuration.jackson;

import com.bpg.spring.boot.security.model.SysUserCompany;
import com.bpg.spring.boot.security.model.UserCompanyContainer;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

/**
 * @author zhaohq
 * create time: 2023/10/12 19:28:26
 */
public class CustomerSysUserCompanyOrganizationDeserializer extends JsonDeserializer<UserCompanyContainer.Organization> {
    @Override
    public UserCompanyContainer.Organization deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JacksonException {
        ObjectMapper mapper = (ObjectMapper) jsonParser.getCodec();
        JsonNode jsonNode = mapper.readTree(jsonParser);

        Long organizationId = JacksonJsonNodeReader.readJsonNode(jsonNode, "organizationId").asLong();
        String organizationName = JacksonJsonNodeReader.readJsonNode(jsonNode, "organizationName").asText();
        String isDefault = JacksonJsonNodeReader.readJsonNode(jsonNode, "isDefault").asText();
        Integer deptId = JacksonJsonNodeReader.readJsonNode(jsonNode, "deptId").asInt();
        String deptName = JacksonJsonNodeReader.readJsonNode(jsonNode, "deptName").asText();

        UserCompanyContainer.Organization organization = new UserCompanyContainer.Organization();
        organization.setOrganizationId(organizationId);
        organization.setOrganizationName(organizationName);
        organization.setIsDefault(isDefault);
        organization.setDeptId(deptId);
        organization.setDeptName(deptName);
        return organization;
    }
}
