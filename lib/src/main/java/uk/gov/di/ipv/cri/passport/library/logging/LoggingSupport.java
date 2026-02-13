package uk.gov.di.ipv.cri.passport.library.logging;

import org.slf4j.MDC;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class LoggingSupport {
    private static final String GOVUK_SIGNIN_JOURNEY_ID = "govuk_signin_journey_id";

    private LoggingSupport() {
        throw new IllegalStateException("Instantiation is not valid for this class.");
    }

    public static void populateLambdaInitLoggerValues() {
        // function_arn and function_request_id are only populated on first handler call after init
        MDC.put("function_name", System.getenv("AWS_LAMBDA_FUNCTION_NAME"));
        MDC.put("function_version", System.getenv("AWS_LAMBDA_FUNCTION_VERSION"));
        MDC.put("service", System.getenv("POWERTOOLS_SERVICE_NAME"));
    }

    public static void clearPersistentJourneyKeys() {
        MDC.remove(GOVUK_SIGNIN_JOURNEY_ID);
    }
}
