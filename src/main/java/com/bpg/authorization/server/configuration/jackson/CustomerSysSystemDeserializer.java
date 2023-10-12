package com.bpg.authorization.server.configuration.jackson;

import com.bpg.spring.boot.security.model.SysSystem;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;

import java.io.IOException;

/**
 * @author zhaohq
 * create time: 2023/10/12 19:00:30
 */
public class CustomerSysSystemDeserializer extends JsonDeserializer<SysSystem> {

    @Override
    public SysSystem deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        ObjectMapper mapper = (ObjectMapper) jsonParser.getCodec();
        JsonNode jsonNode = mapper.readTree(jsonParser);

        Integer systemId = JacksonJsonNodeReader.readJsonNode(jsonNode, "systemId").asInt();
        String systemName = JacksonJsonNodeReader.readJsonNode(jsonNode, "systemName").asText();
        String systemCode = JacksonJsonNodeReader.readJsonNode(jsonNode, "systemCode").asText();
        String icon = JacksonJsonNodeReader.readJsonNode(jsonNode, "icon").asText();
        String color = JacksonJsonNodeReader.readJsonNode(jsonNode, "color").asText();
        String container = JacksonJsonNodeReader.readJsonNode(jsonNode, "container").asText();
        String defaultRegister = JacksonJsonNodeReader.readJsonNode(jsonNode, "defaultRegister").asText();
        String entry = JacksonJsonNodeReader.readJsonNode(jsonNode, "entry").asText();
        String routerBase = JacksonJsonNodeReader.readJsonNode(jsonNode, "routerBase").asText();

        SysSystem sysSystem = new SysSystem();
        sysSystem.setSystemId(systemId);
        sysSystem.setSystemName(systemName);
        sysSystem.setSystemCode(systemCode);
        sysSystem.setIcon(icon);
        sysSystem.setColor(color);
        sysSystem.setContainer(container);
        sysSystem.setContainer(container);
        sysSystem.setDefaultRegister(defaultRegister);
        sysSystem.setEntry(entry);
        sysSystem.setRouterBase(routerBase);

        return sysSystem;
    }
}
