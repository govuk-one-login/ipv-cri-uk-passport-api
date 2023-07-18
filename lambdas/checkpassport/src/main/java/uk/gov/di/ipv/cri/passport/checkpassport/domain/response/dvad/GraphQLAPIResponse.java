package uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.ResponseData;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.errors.Errors;

import java.util.List;

// Ignore everything but the data or error segment,
// which is the only part to be mapped
@JsonIgnoreProperties(ignoreUnknown = true)
@Data
@Builder
public class GraphQLAPIResponse {

    @JsonProperty("data")
    private ResponseData data;

    @JsonProperty("errors")
    private List<Errors> errors;

    @JsonCreator
    public GraphQLAPIResponse(
            @JsonProperty(value = "data", required = true) ResponseData data,
            @JsonProperty(value = "errors", required = false) List<Errors> errors) {
        this.data = data;
        this.errors = errors;
    }
}
