package uk.gov.di.ipv.cri.passport.checkpassport.domain.request.dvad;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class Variables {
    @JsonProperty("input")
    private Input input;

    @JsonCreator
    public Variables(@JsonProperty(value = "input", required = true) Input input) {
        this.input = input;
    }
}
