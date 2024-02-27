package uk.gov.di.ipv.cri.passport.library.dvad.services;

import lombok.Builder;

@Builder
// Internal method response not for use outside this package
class GraphQLAPIResponseValidationResult {
    public final boolean valid;
    public final String failureReason;
}
