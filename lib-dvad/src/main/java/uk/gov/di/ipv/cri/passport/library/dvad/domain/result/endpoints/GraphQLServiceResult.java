package uk.gov.di.ipv.cri.passport.library.dvad.domain.result.endpoints;

import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.GraphQLAPIResponse;

public record GraphQLServiceResult(GraphQLAPIResponse graphQLAPIResponse, String requestId) {
    public static GraphQLServiceResultBuilder builder() {
        return new GraphQLServiceResultBuilder();
    }

    public static class GraphQLServiceResultBuilder {
        private GraphQLAPIResponse graphQLAPIResponse;
        private String requestId;

        private GraphQLServiceResultBuilder() {
            // Intended
        }

        public GraphQLServiceResultBuilder graphQLAPIResponse(
                GraphQLAPIResponse graphQLAPIResponse) {
            this.graphQLAPIResponse = graphQLAPIResponse;
            return this;
        }

        public GraphQLServiceResultBuilder requestId(String requestId) {
            this.requestId = requestId;
            return this;
        }

        public GraphQLServiceResult build() {
            return new GraphQLServiceResult(graphQLAPIResponse, requestId);
        }
    }
}
