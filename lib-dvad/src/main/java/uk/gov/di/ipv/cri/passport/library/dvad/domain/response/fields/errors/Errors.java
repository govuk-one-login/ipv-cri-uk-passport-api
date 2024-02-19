package uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields.errors;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@Builder
@Data
public class Errors {
    @JsonProperty("message")
    private String message;

    @JsonProperty("locations")
    private List<Locations> locations;

    @JsonProperty("path")
    private List<String> path;

    @JsonProperty("extensions")
    private Extensions extensions;

    @JsonCreator
    public Errors(
            @JsonProperty(value = "message", required = true) String message,
            @JsonProperty(value = "locations", required = true) List<Locations> locations,
            @JsonProperty(value = "path", required = false) List<String> path,
            @JsonProperty(value = "extensions", required = true) Extensions extensions) {
        this.message = message;
        this.locations = locations;
        this.path = path;
        this.extensions = extensions;
    }
}
