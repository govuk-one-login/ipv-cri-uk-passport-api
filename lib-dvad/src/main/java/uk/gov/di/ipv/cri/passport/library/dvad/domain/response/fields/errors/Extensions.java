package uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields.errors;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record Extensions(
        @JsonProperty("errorCode") String errorCode,
        // Classification may contain a string or a complex object
        @JsonProperty("classification") @JsonDeserialize(using = ClassificationDeserializer.class)
                String classification) {

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

    public static ExtensionsBuilder builder() {
        return new ExtensionsBuilder();
    }

    public static class ExtensionsBuilder {
        private String errorCode;
        private String classification;

        private ExtensionsBuilder() {
            // Intended
        }

        public ExtensionsBuilder errorCode(String errorCode) {
            this.errorCode = errorCode;
            return this;
        }

        public ExtensionsBuilder classification(String classification) {
            this.classification = classification;
            return this;
        }

        public Extensions build() {
            return new Extensions(errorCode, classification);
        }
    }
}
