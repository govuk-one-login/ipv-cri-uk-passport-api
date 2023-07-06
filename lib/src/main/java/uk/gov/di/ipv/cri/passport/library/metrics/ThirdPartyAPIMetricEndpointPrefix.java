package uk.gov.di.ipv.cri.passport.library.metrics;

/** Not for direct use - see {@link ThirdPartyAPIEndpointMetric} */
public enum ThirdPartyAPIMetricEndpointPrefix {
    // Only one endpoint on DCS API
    DCS_THIRD_PARTY_API_DCS_ENDPOINT,
    // DVAD Api Endpoints
    DVAD_THIRD_PARTY_API_HEALTH_ENDPOINT,
    DVAD_THIRD_PARTY_API_TOKEN_ENDPOINT,
    DVAD_THIRD_PARTY_API_GRAPHQL_ENDPOINT;
}
