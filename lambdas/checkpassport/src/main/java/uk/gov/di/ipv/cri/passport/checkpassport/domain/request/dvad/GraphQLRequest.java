package uk.gov.di.ipv.cri.passport.checkpassport.domain.request.dvad;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class GraphQLRequest {

    @JsonProperty("query")
    private String query;

    @JsonProperty("variables")
    private Variables variables;

    @JsonCreator
    public GraphQLRequest(
            @JsonProperty(value = "query", required = true) String query,
            @JsonProperty(value = "variables", required = true) Variables variables) {
        this.query = query;
        this.variables = variables;
    }
}
