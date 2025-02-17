package uk.gov.di.ipv.cri.passport.library.exceptions;

import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;

/** Exception used to return CRI specific oauth error messages */
@ExcludeFromGeneratedCoverageReport
public class OAuthErrorResponseException extends Exception {
    private final int statusCode;
    private final ErrorResponse errorResponse;

    public OAuthErrorResponseException(int statusCode, ErrorResponse errorResponse) {
        this.statusCode = statusCode;
        this.errorResponse = errorResponse;
    }

    public String getErrorReason() {
        return this.errorResponse.getMessage();
    }

    public int getStatusCode() {
        return this.statusCode;
    }
}
