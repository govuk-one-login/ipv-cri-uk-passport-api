package uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
@Builder
public class ResponseData {

    @JsonProperty("validatePassport")
    private Map<String, String> validatePassport;

    @JsonCreator
    public ResponseData(
            @JsonProperty(value = "validatePassport", required = false)
                    Map<String, String> validatePassport) {
        this.validatePassport = validatePassport;
    }
}
