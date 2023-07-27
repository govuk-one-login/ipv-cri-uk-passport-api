package uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.errors;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class Extensions {
    @JsonProperty("classification")
    private Classification classification;

    @JsonCreator
    public Extensions(
            @JsonProperty(value = "classification", required = true)
                    Classification classification) {
        this.classification = classification;
    }
}
