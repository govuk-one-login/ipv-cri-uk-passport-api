package uk.gov.di.ipv.cri.passport.checkpassport.util;

import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

public class HTTPReply {
    public final int statusCode;
    public final String responseBody;

    public HTTPReply(int statusCode, String responseBody) {
        this.statusCode = statusCode;
        this.responseBody = responseBody;
    }

    @ExcludeFromGeneratedCoverageReport
    private HTTPReply() {
        statusCode = -1;
        responseBody = null;

        throw new IllegalStateException("Not Valid to call no args constructor for this class");
    }
}
