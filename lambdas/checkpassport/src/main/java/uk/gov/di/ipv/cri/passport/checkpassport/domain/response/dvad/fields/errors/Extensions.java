package uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.errors;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.Builder;
import lombok.Data;

import java.io.IOException;

@Builder
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Extensions {

    @JsonProperty("errorCode")
    private String errorCode;

    // Classification may contain a string or a complex object
    @JsonProperty("classification")
    @JsonDeserialize(using = ClassificationDeserializer.class)
    private String classification;

    @JsonCreator
    public Extensions(
            @JsonProperty(value = "errorCode", required = false) String errorCode,
            @JsonProperty(value = "classification", required = true) String classification) {
        this.errorCode = errorCode;
        this.classification = classification;
    }

    private static class ClassificationDeserializer extends JsonDeserializer<String> {
        @Override
        public String deserialize(
                JsonParser jsonParser, DeserializationContext deserializationContext)
                throws IOException {

            JsonNode node = jsonParser.getCodec().readTree(jsonParser);
            JsonNodeType nodeType = node.getNodeType();

            if (nodeType.equals(JsonNodeType.OBJECT)) {
                ObjectNode objectNode = (ObjectNode) node;
                return objectNode.toString();
            } else {
                // JsonNodeType.STRING
                return node.textValue();
            }
        }
    }
}
