package uk.gov.di.ipv.cri.passport.checkpassport.exception;

import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;

@ExcludeFromGeneratedCoverageReport
public class OAuthHttpResponseExceptionWithErrorBody extends HttpResponseExceptionWithErrorBody {
    public OAuthHttpResponseExceptionWithErrorBody(int statusCode, ErrorResponse errorResponse) {
        super(statusCode, errorResponse);
    }
}
