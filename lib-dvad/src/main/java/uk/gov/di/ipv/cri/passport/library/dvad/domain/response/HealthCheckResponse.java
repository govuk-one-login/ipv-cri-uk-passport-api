package uk.gov.di.ipv.cri.passport.library.dvad.domain.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record HealthCheckResponse(@JsonProperty(value = "status", required = true) String status) {
    public static HealthCheckResponseBuilder builder() {
        return new HealthCheckResponseBuilder();
    }

    public static class HealthCheckResponseBuilder {
        private String status;

        private HealthCheckResponseBuilder() {
            // Intended
        }

        public HealthCheckResponseBuilder status(String status) {
            this.status = status;
            return this;
        }

        public HealthCheckResponse build() {
            return new HealthCheckResponse(status);
        }
    }
}
