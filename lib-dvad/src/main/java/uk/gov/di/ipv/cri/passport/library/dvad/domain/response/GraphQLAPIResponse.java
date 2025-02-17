package uk.gov.di.ipv.cri.passport.library.dvad.domain.response;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields.ResponseData;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields.errors.Errors;

import java.util.List;

// Ignore everything but the data or error segment,
// which is the only part to be mapped
@JsonIgnoreProperties(ignoreUnknown = true)
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

    private GraphQLAPIResponse() {
        // Intended
    }

    public ResponseData getData() {
        return data;
    }

    public List<Errors> getErrors() {
        return errors;
    }

    public static GraphQLServiceResultBuilder builder() {
        return new GraphQLServiceResultBuilder();
    }

    public static class GraphQLServiceResultBuilder {
        private ResponseData data;
        private List<Errors> errors;

        private GraphQLServiceResultBuilder() {
            // Intended
        }

        public GraphQLServiceResultBuilder data(ResponseData data) {
            this.data = data;
            return this;
        }

        public GraphQLServiceResultBuilder errors(List<Errors> errors) {
            this.errors = errors;
            return this;
        }

        public GraphQLAPIResponse build() {
            GraphQLAPIResponse graphQLAPIResponse = new GraphQLAPIResponse();
            graphQLAPIResponse.data = data;
            graphQLAPIResponse.errors = errors;
            return graphQLAPIResponse;
        }
    }
}
