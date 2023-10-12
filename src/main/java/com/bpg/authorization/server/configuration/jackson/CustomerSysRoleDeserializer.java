package com.bpg.authorization.server.configuration.jackson;

import com.bpg.spring.boot.security.model.SysRole;
import com.bpg.spring.boot.security.model.SysSystem;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

/**
 * @author zhaohq
 * create time: 2023/10/12 19:14:47
 */
public class CustomerSysRoleDeserializer extends JsonDeserializer<SysRole> {
    @Override
    public SysRole deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JacksonException {
        ObjectMapper mapper = (ObjectMapper) jsonParser.getCodec();
        JsonNode jsonNode = mapper.readTree(jsonParser);

        Integer roleId = JacksonJsonNodeReader.readJsonNode(jsonNode, "roleId").asInt();
        Integer systemId = JacksonJsonNodeReader.readJsonNode(jsonNode, "systemId").asInt();
        String roleName = JacksonJsonNodeReader.readJsonNode(jsonNode, "roleName").asText();
        String roleCode = JacksonJsonNodeReader.readJsonNode(jsonNode, "roleCode").asText();
        String isAdmin = JacksonJsonNodeReader.readJsonNode(jsonNode, "isAdmin").asText();

        SysRole sysRole = new SysRole();
        sysRole.setSystemId(systemId);
        sysRole.setRoleId(roleId);
        sysRole.setRoleCode(roleCode);
        sysRole.setRoleName(roleName);
        sysRole.setIsAdmin(isAdmin);

        return sysRole;
    }
}
