package uk.gov.di.ipv.cri.passport.library.dvad.domain.request;

import com.fasterxml.jackson.annotation.JsonProperty;

public record GraphQLRequest(
        @JsonProperty(value = "query", required = true) String query,
        @JsonProperty(value = "variables", required = true) Variables variables) {

    public static GraphQLRequestBuilder builder() {
        return new GraphQLRequestBuilder();
    }

    public static class GraphQLRequestBuilder {
        private String query;
        private Variables variables;

        GraphQLRequestBuilder() {
            // Intended
        }

        public GraphQLRequestBuilder query(String query) {
            this.query = query;
            return this;
        }

        public GraphQLRequestBuilder variables(Variables variables) {
            this.variables = variables;
            return this;
        }

        public GraphQLRequest build() {
            return new GraphQLRequest(query, variables);
        }
    }
}
