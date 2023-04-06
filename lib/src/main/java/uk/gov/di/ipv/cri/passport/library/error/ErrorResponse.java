package uk.gov.di.ipv.cri.passport.library.error;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum ErrorResponse {
    FAILED_TO_PARSE_PASSPORT_FORM_DATA(1000, "Failed to parse passport form data"),
    FAILED_TO_PREPARE_DCS_PAYLOAD(1001, "Failed to prepare DCS payload"),
    FAILED_TO_MAP_HTTP_RESPONSE_BODY(1002, "Failed to map http response body"),
    FAILED_TO_UNWRAP_DCS_RESPONSE(1003, "Failed to unwrap Dcs response"),
    DCS_RETURNED_AN_ERROR(1004, "DCS returned an error response"),
    FAILED_TO_SEND_AUDIT_MESSAGE_TO_SQS_QUEUE(
            1005, "Failed to send message to aws SQS audit event queue"),
    ERROR_INVOKING_THIRD_PARTY_API(
            1006, "Error occurred when attempting to invoke the third party api"),
    FORM_DATA_FAILED_VALIDATION(1007, "Form Data failed validation"),
    THIRD_PARTY_ERROR_HTTP_30X(1008, "Third party Responded with a HTTP Redirection status code"),
    THIRD_PARTY_ERROR_HTTP_40X(1009, "Third party Responded with a HTTP Client Error status code"),
    THIRD_PARTY_ERROR_HTTP_50X(1010, "Third party Responded with a HTTP Server Error status code"),
    THIRD_PARTY_ERROR_HTTP_X(1011, "Third party Responded with an unhandled HTTP status code");

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
