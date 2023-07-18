package uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.errors;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Builder
@Data
public class Classification {

    @JsonProperty("type")
    private final String type;

    @JsonProperty("validatedPath")
    private final List<String> validatedPath;

    @JsonProperty("constraint")
    private final String constraint;

    @JsonCreator
    public Classification(
            @JsonProperty(value = "type", required = true) String type,
            @JsonProperty(value = "validatedPath", required = true) List<String> validatedPath,
            @JsonProperty(value = "constraint", required = true) String constraint) {
        this.type = type;
        this.validatedPath = validatedPath;
        this.constraint = constraint;
    }
}
