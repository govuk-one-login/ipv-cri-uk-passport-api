package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad;

import lombok.Builder;

@Builder
// Internal method response not for use outside this package
class GraphQLAPIResponseValidationResult {
    public final boolean valid;
    public final String failureReason;
}
