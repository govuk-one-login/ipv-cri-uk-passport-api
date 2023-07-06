package uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import lombok.Builder;
import lombok.Data;

import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
@Builder
public class ValidatePassportData {

    // Remote processing returns this as null instead of empty
    // This simplifies processing - map guarantied present (just empty)
    @JsonSetter(nulls = Nulls.AS_EMPTY)
    @JsonProperty("matches")
    private Map<String, String> matches;

    @JsonProperty("validationResult")
    private ValidationResult validationResult;

    @JsonProperty("passportFound")
    private boolean passportFound;

    @JsonCreator
    public ValidatePassportData(
            @JsonProperty(value = "matches", required = true) Map<String, String> matches,
            @JsonProperty(value = "validationResult", required = true)
                    ValidationResult validationResult,
            @JsonProperty(value = "passportFound", required = true) boolean passportFound) {
        this.matches = matches;
        this.validationResult = validationResult;
        this.passportFound = passportFound;
    }
}
