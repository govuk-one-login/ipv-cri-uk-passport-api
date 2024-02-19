package uk.gov.di.ipv.cri.passport.library.dvad.domain.response;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
@Builder
public class HealthCheckResponse {

    @JsonProperty("status")
    private String status;

    @JsonCreator
    public HealthCheckResponse(@JsonProperty(value = "status", required = true) String status) {
        this.status = status;
    }
}
