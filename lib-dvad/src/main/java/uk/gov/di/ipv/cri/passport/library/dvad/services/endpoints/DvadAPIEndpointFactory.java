package uk.gov.di.ipv.cri.passport.library.dvad.services.endpoints;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;

import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_ENDPOINT_GRAPHQL;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_ENDPOINT_HEALTH;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_ENDPOINT_TOKEN;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_ENDPOINT_URL;

/** NOTE: Lazy initialization is used for the Services created by this factory. */
public class DvadAPIEndpointFactory {

    private static final String END_POINT_PATH_FORMAT = "%s%s";

    final String healthEndpoint;
    final String tokenEndpoint;
    final String graphQlEndpoint;

    public DvadAPIEndpointFactory(ParameterStoreService parameterStoreService) {

        // Url of the API
        final String hmpoEndPoint = parameterStoreService.getParameterValue(HMPO_API_ENDPOINT_URL);

        // Paths used to accommodate per endpoint versioning i.e "/v1/service..."
        final String healthPath = parameterStoreService.getParameterValue(HMPO_API_ENDPOINT_HEALTH);
        final String tokenPath = parameterStoreService.getParameterValue(HMPO_API_ENDPOINT_TOKEN);
        final String graphQLPath =
                parameterStoreService.getParameterValue(HMPO_API_ENDPOINT_GRAPHQL);

        healthEndpoint = String.format(END_POINT_PATH_FORMAT, hmpoEndPoint, healthPath);
        tokenEndpoint = String.format(END_POINT_PATH_FORMAT, hmpoEndPoint, tokenPath);
        graphQlEndpoint = String.format(END_POINT_PATH_FORMAT, hmpoEndPoint, graphQLPath);
    }

    /**
     * NOTE: Lazy initialization, a service will created for each method call
     *
     * @param closeableHttpClient
     * @param requestConfig
     * @param objectMapper
     * @return HealthCheckService
     */
    public HealthCheckService createHealthCheckService(
            CloseableHttpClient closeableHttpClient,
            RequestConfig requestConfig,
            ObjectMapper objectMapper,
            EventProbe eventProbe) {
        return new HealthCheckService(
                healthEndpoint, closeableHttpClient, requestConfig, objectMapper, eventProbe);
    }

    /**
     * NOTE: Lazy initialization, a service will created for each method call
     *
     * @param closeableHttpClient
     * @param requestConfig
     * @param objectMapper
     * @return TokenRequestService
     */
    public TokenRequestService createTokenRequestService(
            CloseableHttpClient closeableHttpClient,
            RequestConfig requestConfig,
            ObjectMapper objectMapper,
            EventProbe eventProbe) {
        return new TokenRequestService(
                tokenEndpoint, closeableHttpClient, requestConfig, objectMapper, eventProbe);
    }

    /**
     * NOTE: Lazy initialization, a service will created for each method call
     *
     * @param closeableHttpClient
     * @param requestConfig
     * @param objectMapper
     * @param eventProbe
     * @return GraphQLRequestService
     */
    public GraphQLRequestService createGraphQLRequestService(
            CloseableHttpClient closeableHttpClient,
            RequestConfig requestConfig,
            ObjectMapper objectMapper,
            EventProbe eventProbe) {
        return new GraphQLRequestService(
                graphQlEndpoint, closeableHttpClient, requestConfig, objectMapper, eventProbe);
    }
}
