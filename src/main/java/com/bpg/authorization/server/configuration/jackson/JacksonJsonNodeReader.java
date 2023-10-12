package com.bpg.authorization.server.configuration.jackson;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.MissingNode;

/**
 * @author zhaohq
 * create time: 2023/10/12 19:16:12
 */
public class JacksonJsonNodeReader {
    public static JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }
}
