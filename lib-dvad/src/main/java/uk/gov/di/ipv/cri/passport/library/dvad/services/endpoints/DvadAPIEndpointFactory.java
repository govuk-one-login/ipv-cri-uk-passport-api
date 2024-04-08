package uk.gov.di.ipv.cri.passport.library.dvad.services.endpoints;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.domain.Strategy;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;

import java.util.Map;

import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_ENDPOINT_GRAPHQL;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_ENDPOINT_HEALTH;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_ENDPOINT_TOKEN;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_ENDPOINT_URL;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.TEST_STRATEGY_HMPO_API_ENDPOINT_URL;

/** NOTE: Lazy initialization is used for the Services created by this factory. */
@ExcludeFromGeneratedCoverageReport
public class DvadAPIEndpointFactory {

    private static final String END_POINT_PATH_FORMAT = "%s%s";
    final Map<String, String> hmpoEndPoints;
    final String healthPath;
    final String tokenPath;
    final String graphQLPath;

    // Below variable is for continued implementation of pre testData strategy approach
    final String hmpoEndPoint;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public DvadAPIEndpointFactory(ParameterStoreService parameterStoreService)
            throws JsonProcessingException {

        // Url of the API
        hmpoEndPoint = parameterStoreService.getParameterValue(HMPO_API_ENDPOINT_URL);
        // Below for use in testDataStrategy, above hmpoEndpoint is kept to avoid any functional
        // change before it's live
        hmpoEndPoints =
                constructParameterMap(
                        parameterStoreService.getParameterValue(
                                TEST_STRATEGY_HMPO_API_ENDPOINT_URL));

        // Paths used to accommodate per endpoint versioning i.e "/v1/service..."
        healthPath = parameterStoreService.getParameterValue(HMPO_API_ENDPOINT_HEALTH);
        tokenPath = parameterStoreService.getParameterValue(HMPO_API_ENDPOINT_TOKEN);
        graphQLPath = parameterStoreService.getParameterValue(HMPO_API_ENDPOINT_GRAPHQL);
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
            EventProbe eventProbe,
            Strategy strategy) {
        String hmpoEndpoint = hmpoEndPoints.get(strategy.name());
        final String healthEndpoint =
                String.format(END_POINT_PATH_FORMAT, hmpoEndpoint, healthPath);

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
            EventProbe eventProbe,
            Strategy strategy) {
        String hmpoEndpoint = hmpoEndPoints.get(strategy.name());
        final String tokenEndpoint = String.format(END_POINT_PATH_FORMAT, hmpoEndpoint, tokenPath);
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
            EventProbe eventProbe,
            Strategy strategy) {
        String hmpoEndpoint = hmpoEndPoints.get(strategy.name());
        final String graphQlEndpoint =
                String.format(END_POINT_PATH_FORMAT, hmpoEndpoint, graphQLPath);
        return new GraphQLRequestService(
                graphQlEndpoint, closeableHttpClient, requestConfig, objectMapper, eventProbe);
    }

    public Map<String, String> constructParameterMap(String parameterValue)
            throws JsonProcessingException {
        return objectMapper.readValue(parameterValue, Map.class);
    }
}
