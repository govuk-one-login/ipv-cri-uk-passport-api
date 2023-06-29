package uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class Extensions {
    @JsonProperty("code")
    private String code;

    @JsonCreator
    public Extensions(@JsonProperty(value = "code", required = false) String code) {
        this.code = code;
    }
}
