package uk.gov.di.ipv.cri.passport.library.logging;

import org.slf4j.MDC;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class LoggingSupport {
    private LoggingSupport() {
        throw new IllegalStateException("Instantiation is not valid for this class.");
    }

    /**
     * Unlike Powertools v1, Powertools v2 does not populate logging keys during Lambda INIT. This
     * method replicates some of the v1 functionality by populating {@code function_name}, {@code
     * function_version}, and {@code service} during INIT. The keys {@code function_arn} and {@code
     * function_request_id} can only be populated in the first handler call after INIT and is
     * performed automatically by Powertools v2.
     *
     * <p>In the Lambda handler this method should be called in a static block immediately after the
     * static Lambda logger is created.
     */
    public static void populateLambdaInitLoggerValues() {
        // function_arn and function_request_id are only populated on first handler call after init
        MDC.put("function_name", System.getenv("AWS_LAMBDA_FUNCTION_NAME"));
        MDC.put("function_version", System.getenv("AWS_LAMBDA_FUNCTION_VERSION"));
        MDC.put("service", System.getenv("POWERTOOLS_SERVICE_NAME"));
    }
}
