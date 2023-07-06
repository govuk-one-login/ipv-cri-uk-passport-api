package uk.gov.di.ipv.cri.passport.library.metrics;

/** Not for direct use - see {@link ThirdPartyAPIEndpointMetric} */
public enum ThirdPartyAPIEndpointMetricType {
    REQUEST_CREATED,
    REQUEST_SEND_OK,
    REQUEST_SEND_ERROR,
    API_RESPONSE_TYPE_VALID,
    API_RESPONSE_TYPE_INVALID,
    API_RESPONSE_TYPE_ERROR,
    API_RESPONSE_TYPE_EXPECTED_HTTP_STATUS,
    API_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS;
}
