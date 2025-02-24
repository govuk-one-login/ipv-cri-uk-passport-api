package uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields.errors;

import com.fasterxml.jackson.annotation.JsonProperty;

public record Locations(
        @JsonProperty(value = "line", required = true) String line,
        @JsonProperty(value = "column", required = true) String column) {

    public static LocationsBuilder builder() {
        return new LocationsBuilder();
    }

    public static class LocationsBuilder {
        private String line;
        private String column;

        public LocationsBuilder line(String line) {
            this.line = line;
            return this;
        }

        public LocationsBuilder column(String column) {
            this.column = column;
            return this;
        }

        public Locations build() {
            return new Locations(line, column);
        }
    }
}
