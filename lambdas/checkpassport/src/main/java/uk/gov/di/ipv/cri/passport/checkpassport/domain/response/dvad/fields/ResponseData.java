package uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
@Builder
public class ResponseData {

    @JsonProperty("validatePassportData")
    private ValidatePassportData validatePassportData;

    @JsonCreator
    public ResponseData(
            @JsonProperty(value = "validatePassportData", required = true)
                    ValidatePassportData validatePassportData) {
        this.validatePassportData = validatePassportData;
    }
}
