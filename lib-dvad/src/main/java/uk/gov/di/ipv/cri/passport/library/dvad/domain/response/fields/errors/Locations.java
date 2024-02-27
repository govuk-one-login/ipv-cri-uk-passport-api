package uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields.errors;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class Locations {

    @JsonProperty("line")
    private final String line;

    @JsonProperty("column")
    private final String column;

    @JsonCreator
    public Locations(
            @JsonProperty(value = "line", required = true) String line,
            @JsonProperty(value = "column", required = true) String column) {
        this.line = line;
        this.column = column;
    }
}
