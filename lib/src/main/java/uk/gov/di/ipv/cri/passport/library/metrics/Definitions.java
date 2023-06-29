package uk.gov.di.ipv.cri.passport.library.metrics;

import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

public class Definitions {

    // These completed metrics record all escape routes from the lambdas.
    // OK for expected routes with ERROR being all others
    public static final String LAMBDA_CHECK_PASSPORT_COMPLETED_OK =
            "lambda_check_passport_completed_ok";
    public static final String LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR =
            "lambda_check_passport_completed_error";

    public static final String LAMBDA_ISSUE_CREDENTIAL_COMPLETED_OK =
            "lambda_issue_credential_completed_ok";
    public static final String LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR =
            "lambda_issue_credential_completed_error";

    // Document Data Status after an attempt
    public static final String LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_VERIFIED_PREFIX =
            "lambda_check_passport_attempt_status_verified_"; // Attempt count appended
    public static final String LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_RETRY =
            "lambda_check_passport_attempt_status_retry";
    public static final String LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_UNVERIFIED =
            "lambda_check_passport_attempt_status_unverified";

    // Users who have reached max attempts and have gone back to the form, but will be redirected
    public static final String LAMBDA_CHECK_PASSPORT_USER_REDIRECTED_ATTEMPTS_OVER_MAX =
            "lambda_check_passport_user_redirected_attempts_over_max";

    // FormDataParse
    public static final String FORM_DATA_PARSE_PASS = "form_data_parse_pass";
    public static final String FORM_DATA_PARSE_FAIL = "form_data_parse_fail";

    // FormDataValidator
    public static final String FORM_DATA_VALIDATION_PASS = "form_data_validation_pass";
    public static final String FORM_DATA_VALIDATION_FAIL = "form_data_validation_fail";

    // DocumentDataVerification (Request Status)
    public static final String DOCUMENT_DATA_VERIFICATION_REQUEST_SUCCEEDED =
            "document_data_verification_request_succeeded";
    public static final String DOCUMENT_DATA_VERIFICATION_REQUEST_FAILED =
            "document_data_verification_request_failed";

    public static final String PASSPORT_CI_PREFIX = "passport_ci_";

    // ThirdPartyAPIService metrics in Passport are recorded per API (DCS/DVAD)
    // For DVAD they are also recorded Per API Endpoint individually
    // See ThirdPartyAPIEndpointMetric

    @ExcludeFromGeneratedCoverageReport
    private Definitions() {
        throw new IllegalStateException("Instantiation is not valid for this class.");
    }
}
