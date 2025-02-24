package uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ResponseData {

    @JsonProperty("validatePassport")
    private Map<String, String> validatePassport;

    @JsonCreator
    public ResponseData(
            @JsonProperty(value = "validatePassport", required = false)
                    Map<String, String> validatePassport) {
        this.validatePassport = validatePassport;
    }

    private ResponseData() {
        // Intended
    }

    public Map<String, String> getValidatePassport() {
        return validatePassport;
    }

    public static ResponseDataBuilder builder() {
        return new ResponseDataBuilder();
    }

    public static class ResponseDataBuilder {
        private Map<String, String> validatePassport;

        private ResponseDataBuilder() {
            // Intended
        }

        public ResponseDataBuilder validatePassport(Map<String, String> validatePassport) {
            this.validatePassport = validatePassport;
            return this;
        }

        public ResponseData build() {
            ResponseData responseData = new ResponseData();
            responseData.validatePassport = validatePassport;
            return responseData;
        }
    }
}
