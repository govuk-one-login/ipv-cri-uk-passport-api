package uk.gov.di.ipv.cri.passport.library.metrics;

import uk.gov.di.ipv.cri.passport.library.exceptions.MetricException;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;

import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetricType.API_RESPONSE_TYPE_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetricType.API_RESPONSE_TYPE_EXPECTED_HTTP_STATUS;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetricType.API_RESPONSE_TYPE_INVALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetricType.API_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetricType.API_RESPONSE_TYPE_VALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetricType.REQUEST_CREATED;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetricType.REQUEST_SEND_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetricType.REQUEST_SEND_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIMetricEndpointPrefix.DCS_THIRD_PARTY_API_DCS_ENDPOINT;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIMetricEndpointPrefix.DVAD_THIRD_PARTY_API_GRAPHQL_ENDPOINT;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIMetricEndpointPrefix.DVAD_THIRD_PARTY_API_HEALTH_ENDPOINT;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIMetricEndpointPrefix.DVAD_THIRD_PARTY_API_TOKEN_ENDPOINT;

public enum ThirdPartyAPIEndpointMetric {

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // DCS End Point Metrics                                                                     //
    ///////////////////////////////////////////////////////////////////////////////////////////////
    DCS_REQUEST_CREATED(DCS_THIRD_PARTY_API_DCS_ENDPOINT, REQUEST_CREATED),
    DCS_REQUEST_SEND_OK(DCS_THIRD_PARTY_API_DCS_ENDPOINT, REQUEST_SEND_OK),
    DCS_REQUEST_SEND_ERROR(DCS_THIRD_PARTY_API_DCS_ENDPOINT, REQUEST_SEND_ERROR),

    DCS_RESPONSE_TYPE_VALID(DCS_THIRD_PARTY_API_DCS_ENDPOINT, API_RESPONSE_TYPE_VALID),
    DCS_RESPONSE_TYPE_INVALID(DCS_THIRD_PARTY_API_DCS_ENDPOINT, API_RESPONSE_TYPE_INVALID),

    DCS_RESPONSE_TYPE_ERROR(DCS_THIRD_PARTY_API_DCS_ENDPOINT, API_RESPONSE_TYPE_ERROR),

    DCS_RESPONSE_TYPE_EXPECTED_HTTP_STATUS(
            DCS_THIRD_PARTY_API_DCS_ENDPOINT, API_RESPONSE_TYPE_EXPECTED_HTTP_STATUS),
    DCS_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS(
            DCS_THIRD_PARTY_API_DCS_ENDPOINT, API_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS),

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // DVAD Health End Point Metrics                                                             //
    ///////////////////////////////////////////////////////////////////////////////////////////////
    DVAD_HEALTH_REQUEST_CREATED(DVAD_THIRD_PARTY_API_HEALTH_ENDPOINT, REQUEST_CREATED),
    DVAD_HEALTH_REQUEST_SEND_OK(DVAD_THIRD_PARTY_API_HEALTH_ENDPOINT, REQUEST_SEND_OK),
    DVAD_HEALTH_REQUEST_SEND_ERROR(DVAD_THIRD_PARTY_API_HEALTH_ENDPOINT, REQUEST_SEND_ERROR),

    DVAD_HEALTH_RESPONSE_TYPE_VALID(DVAD_THIRD_PARTY_API_HEALTH_ENDPOINT, API_RESPONSE_TYPE_VALID),
    DVAD_HEALTH_RESPONSE_TYPE_INVALID(
            DVAD_THIRD_PARTY_API_HEALTH_ENDPOINT, API_RESPONSE_TYPE_INVALID),

    DVAD_HEALTH_RESPONSE_STATUS_UP(DVAD_THIRD_PARTY_API_HEALTH_ENDPOINT, "UP"),
    DVAD_HEALTH_RESPONSE_STATUS_DOWN(DVAD_THIRD_PARTY_API_HEALTH_ENDPOINT, "DOWN"),

    DVAD_HEALTH_RESPONSE_TYPE_EXPECTED_HTTP_STATUS(
            DVAD_THIRD_PARTY_API_HEALTH_ENDPOINT, API_RESPONSE_TYPE_EXPECTED_HTTP_STATUS),
    DVAD_HEALTH_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS(
            DVAD_THIRD_PARTY_API_HEALTH_ENDPOINT, API_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS),

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // DVAD Token End Point Metrics                                                              //
    ///////////////////////////////////////////////////////////////////////////////////////////////
    DVAD_TOKEN_REQUEST_CREATED(DVAD_THIRD_PARTY_API_TOKEN_ENDPOINT, REQUEST_CREATED),
    DVAD_TOKEN_REQUEST_SEND_OK(DVAD_THIRD_PARTY_API_TOKEN_ENDPOINT, REQUEST_SEND_OK),

    DVAD_TOKEN_REQUEST_SEND_ERROR(DVAD_THIRD_PARTY_API_TOKEN_ENDPOINT, REQUEST_SEND_ERROR),

    DVAD_TOKEN_RESPONSE_TYPE_VALID(DVAD_THIRD_PARTY_API_TOKEN_ENDPOINT, API_RESPONSE_TYPE_VALID),
    DVAD_TOKEN_RESPONSE_TYPE_INVALID(
            DVAD_THIRD_PARTY_API_TOKEN_ENDPOINT, API_RESPONSE_TYPE_INVALID),

    DVAD_TOKEN_RESPONSE_TYPE_EXPECTED_HTTP_STATUS(
            DVAD_THIRD_PARTY_API_TOKEN_ENDPOINT, API_RESPONSE_TYPE_EXPECTED_HTTP_STATUS),
    DVAD_TOKEN_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS(
            DVAD_THIRD_PARTY_API_TOKEN_ENDPOINT, API_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS),

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // DVAD GraphQL End Point Metrics                                                            //
    ///////////////////////////////////////////////////////////////////////////////////////////////
    DVAD_GRAPHQL_REQUEST_CREATED(DVAD_THIRD_PARTY_API_GRAPHQL_ENDPOINT, REQUEST_CREATED),
    DVAD_GRAPHQL_REQUEST_SEND_OK(DVAD_THIRD_PARTY_API_GRAPHQL_ENDPOINT, REQUEST_SEND_OK),
    DVAD_GRAPHQL_REQUEST_SEND_ERROR(DVAD_THIRD_PARTY_API_GRAPHQL_ENDPOINT, REQUEST_SEND_ERROR),

    DVAD_GRAPHQL_RESPONSE_TYPE_VALID(
            DVAD_THIRD_PARTY_API_GRAPHQL_ENDPOINT, API_RESPONSE_TYPE_VALID),
    DVAD_GRAPHQL_RESPONSE_TYPE_INVALID(
            DVAD_THIRD_PARTY_API_GRAPHQL_ENDPOINT, API_RESPONSE_TYPE_INVALID),
    DVAD_GRAPHQL_RESPONSE_TYPE_ERROR(
            DVAD_THIRD_PARTY_API_GRAPHQL_ENDPOINT, API_RESPONSE_TYPE_ERROR),

    DVAD_GRAPHQL_RESPONSE_TYPE_EXPECTED_HTTP_STATUS(
            DVAD_THIRD_PARTY_API_GRAPHQL_ENDPOINT, API_RESPONSE_TYPE_EXPECTED_HTTP_STATUS),
    DVAD_GRAPHQL_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS(
            DVAD_THIRD_PARTY_API_GRAPHQL_ENDPOINT, API_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS),
    ;

    private static final String METRIC_FORMAT = "%s_%s";
    private static final String METRIC_CAUSE_FORMAT = METRIC_FORMAT;

    private final String metricWithEndpointPrefix;

    // To avoid copy and paste errors in the alternative large list of string mappings for each
    // endpoint metric combo
    ThirdPartyAPIEndpointMetric(
            ThirdPartyAPIMetricEndpointPrefix prefix, ThirdPartyAPIEndpointMetricType metricType) {
        String endPointPrefixLowerCase = prefix.toString().toLowerCase();
        String metricTypeLowercase = metricType.toString().toLowerCase();
        this.metricWithEndpointPrefix =
                String.format(METRIC_FORMAT, endPointPrefixLowerCase, metricTypeLowercase);
    }

    // To allow special case metrics that do not apply to all endpoints (eg UP/DOWN health)
    ThirdPartyAPIEndpointMetric(ThirdPartyAPIMetricEndpointPrefix prefix, String metric) {
        String endPointPrefixLowerCase = prefix.toString().toLowerCase();
        String metricLowercase = metric.toLowerCase();
        this.metricWithEndpointPrefix =
                String.format(METRIC_FORMAT, endPointPrefixLowerCase, metricLowercase);
    }

    public String withEndpointPrefix() {
        return metricWithEndpointPrefix;
    }

    /**
     * Created for attaching Exception to REQUEST_SEND_ERROR - format effectively - %s_%s_%s. NOTE:
     * invalid to provide OAuthErrorResponseException. OAuthErrorResponseException is a generated
     * exception, metrics should only capture caught executions.
     *
     * @return String in the format endpont_metric_exceptionname
     */
    public String withEndpointPrefixAndExceptionName(Exception e) {
        if (e instanceof OAuthErrorResponseException) {
            // OAuthErrorResponseException is a generated exception,
            // metrics should only capture caught executions
            throw new MetricException(
                    "OAuthErrorResponseException is not a valid exception for metrics");
        }

        return String.format(
                METRIC_CAUSE_FORMAT, metricWithEndpointPrefix, e.getClass().getSimpleName());
    }
}
