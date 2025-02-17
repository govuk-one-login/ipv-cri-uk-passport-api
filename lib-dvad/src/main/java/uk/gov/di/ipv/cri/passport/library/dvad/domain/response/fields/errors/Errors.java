package uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields.errors;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record Errors(
        @JsonProperty("message") String message,
        @JsonProperty("locations") List<Locations> locations,
        @JsonProperty("path") List<String> path,
        @JsonProperty("extensions") Extensions extensions) {

    public static ErrorsBuilder builder() {
        return new ErrorsBuilder();
    }

    public static class ErrorsBuilder {
        private String message;
        private List<Locations> locations;
        private List<String> path;
        private Extensions extensions;

        private ErrorsBuilder() {
            // Intended
        }

        public ErrorsBuilder message(String message) {
            this.message = message;
            return this;
        }

        public ErrorsBuilder locations(List<Locations> locations) {
            this.locations = locations;
            return this;
        }

        public ErrorsBuilder path(List<String> path) {
            this.path = path;
            return this;
        }

        public ErrorsBuilder extensions(Extensions extensions) {
            this.extensions = extensions;
            return this;
        }

        public Errors build() {
            return new Errors(message, locations, path, extensions);
        }
    }
}
