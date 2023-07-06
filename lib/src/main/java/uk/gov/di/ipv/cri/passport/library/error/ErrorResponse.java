package uk.gov.di.ipv.cri.passport.library.error;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

@JsonFormat(shape = JsonFormat.Shape.OBJECT)
@ExcludeFromGeneratedCoverageReport
public enum ErrorResponse {
    FAILED_TO_PARSE_PASSPORT_FORM_DATA(1000, "Failed to parse passport form data"),
    FORM_DATA_FAILED_VALIDATION(1001, "Form Data failed validation"),

    // Common to DCS + DVAD
    FAILED_TO_RETRIEVE_HTTP_RESPONSE_BODY(1101, "Failed to retrieve http response body"),

    // DCS
    FAILED_TO_PREPARE_DCS_PAYLOAD(1101, "Failed to prepare Dcs payload"),
    FAILED_TO_UNWRAP_DCS_RESPONSE(1102, "Failed to unwrap Dcs response"),
    ERROR_INVOKING_LEGACY_THIRD_PARTY_API(
            1103, "Error occurred when attempting to invoke the legacy third party api"),
    DCS_RETURNED_AN_ERROR_RESPONSE(1104, "DCS returned an error response"),
    ERROR_DCS_RETURNED_UNEXPECTED_HTTP_STATUS_CODE(
            1105, "dcs returned unexpected http status code"),

    // DVAD
    ERROR_INVOKING_THIRD_PARTY_API_HEALTH_ENDPOINT(
            1201, "Error occurred when attempting to invoke the third party api health endpoint"),
    ERROR_THIRD_PARTY_API_HEALTH_ENDPOINT_NOT_UP(1202, "Third party api is status is not \"UP\""),
    FAILED_TO_MAP_HEALTH_ENDPOINT_RESPONSE_BODY(
            1203, "Failed to map health endpoint response body"),

    ERROR_INVOKING_THIRD_PARTY_API_TOKEN_ENDPOINT(
            1204, "Error occurred when attempting to invoke the third party api token endpoint"),
    FAILED_TO_VERIFY_ACCESS_TOKEN(1205, "Failed to verify access token"),
    FAILED_TO_MAP_TOKEN_ENDPOINT_RESPONSE_BODY(1206, "Failed to map token endpoint response body"),
    ERROR_TOKEN_ENDPOINT_RETURNED_UNEXPECTED_HTTP_STATUS_CODE(
            1207, "token endpoint returned unexpected http status code"),

    FAILED_TO_PREPARE_GRAPHQL_REQUEST_PAYLOAD(1208, "Failed to prepare graphql request payload"),
    ERROR_INVOKING_THIRD_PARTY_API_GRAPHQL_ENDPOINT(
            1209, "Error occurred when attempting to invoke the third party api graphql endpoint"),
    FAILED_TO_MAP_GRAPHQL_ENDPOINT_RESPONSE_BODY(
            1210, "Failed to map graphql endpoint response body"),
    ERROR_GRAPHQL_ENDPOINT_RETURNED_UNEXPECTED_HTTP_STATUS_CODE(
            1211, "graphql endpoint returned unexpected http status code"),

    GRAPHQL_ENDPOINT_RETURNED_AN_ERROR_RESPONSE(
            1212, "graphql endpoint returned an error response"),
    DVAD_API_RESPONSE_NOT_VALID(1213, "dvad api response not valid"),

    FAILED_TO_SEND_AUDIT_MESSAGE_TO_SQS_QUEUE(
            1401, "Failed to send message to aws SQS audit event queue");

    private final int code;
    private final String message;

    ErrorResponse(
            @JsonProperty(required = true, value = "code") int code,
            @JsonProperty(required = true, value = "message") String message) {
        this.code = code;
        this.message = message;
    }

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public String getErrorSummary() {
        return getCode() + ": " + getMessage();
    }
}
