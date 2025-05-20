package uk.gov.di.ipv.cri.passport.library.logging;

import software.amazon.lambda.powertools.logging.LoggingUtils;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

public class LoggingSupport {
    private static final String GOVUK_SIGNIN_JOURNEY_ID = "govuk_signin_journey_id";

    @ExcludeFromGeneratedCoverageReport
    private LoggingSupport() {
        throw new IllegalStateException("Instantiation is not valid for this class.");
    }

    public static void clearPersistentJourneyKeys() {
        LoggingUtils.removeKey(GOVUK_SIGNIN_JOURNEY_ID);
    }
}
