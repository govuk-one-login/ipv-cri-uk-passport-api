package uk.gov.di.ipv.cri.passport.library.dvad.services;

// Internal method response not for use outside this package
public record GraphQLAPIResponseValidationResult(boolean valid, String failureReason) {

    public static GraphQLAPIResponseValidationResultBuilder builder() {
        return new GraphQLAPIResponseValidationResultBuilder();
    }

    public static class GraphQLAPIResponseValidationResultBuilder {
        private boolean valid;
        private String failureReason;

        private GraphQLAPIResponseValidationResultBuilder() {
            // Intended
        }

        public GraphQLAPIResponseValidationResultBuilder valid(boolean valid) {
            this.valid = valid;
            return this;
        }

        public GraphQLAPIResponseValidationResultBuilder failureReason(String failureReason) {
            this.failureReason = failureReason;
            return this;
        }

        public GraphQLAPIResponseValidationResult build() {
            return new GraphQLAPIResponseValidationResult(valid, failureReason);
        }
    }
}
