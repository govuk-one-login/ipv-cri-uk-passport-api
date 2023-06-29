package uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class Errors {
    @JsonProperty("message")
    private String message;

    @JsonProperty("extensions")
    private Extensions extensions;

    @JsonCreator
    public Errors(
            @JsonProperty(value = "message", required = false) String message,
            @JsonProperty(value = "extensions", required = false) Extensions extensions) {
        this.message = message;
        this.extensions = extensions;
    }
}
