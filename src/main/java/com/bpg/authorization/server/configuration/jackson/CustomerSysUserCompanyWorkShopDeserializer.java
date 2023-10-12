package com.bpg.authorization.server.configuration.jackson;

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
 * create time: 2023/10/12 19:33:38
 */
public class CustomerSysUserCompanyWorkShopDeserializer extends JsonDeserializer<UserCompanyContainer.WorkShop> {
    @Override
    public UserCompanyContainer.WorkShop deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JacksonException {
        ObjectMapper mapper = (ObjectMapper) jsonParser.getCodec();
        JsonNode jsonNode = mapper.readTree(jsonParser);

        Long organizationId = JacksonJsonNodeReader.readJsonNode(jsonNode, "organizationId").asLong();
        Long workshopId = JacksonJsonNodeReader.readJsonNode(jsonNode, "workshopId").asLong();
        String organizationName = JacksonJsonNodeReader.readJsonNode(jsonNode, "organizationName").asText();
        String workshopName = JacksonJsonNodeReader.readJsonNode(jsonNode, "workshopName").asText();
        String isDefault = JacksonJsonNodeReader.readJsonNode(jsonNode, "isDefault").asText();
        Integer deptId = JacksonJsonNodeReader.readJsonNode(jsonNode, "deptId").asInt();
        String deptName = JacksonJsonNodeReader.readJsonNode(jsonNode, "deptName").asText();

        UserCompanyContainer.WorkShop workShop = new UserCompanyContainer.WorkShop();
        workShop.setWorkshopId(workshopId);
        workShop.setWorkshopName(workshopName);
        workShop.setOrganizationId(organizationId);
        workShop.setOrganizationName(organizationName);
        workShop.setIsDefault(isDefault);
        workShop.setDeptId(deptId);
        workShop.setDeptName(deptName);
        return workShop;
    }
}
