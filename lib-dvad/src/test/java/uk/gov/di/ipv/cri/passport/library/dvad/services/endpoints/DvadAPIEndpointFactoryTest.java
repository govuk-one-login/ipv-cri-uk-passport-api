package uk.gov.di.ipv.cri.passport.library.dvad.services.endpoints;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.account.ipv.cri.lime.limeade.strategy.Strategy;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_ENDPOINT_GRAPHQL;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_ENDPOINT_HEALTH;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_ENDPOINT_TOKEN;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_ENDPOINT_URL;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.TEST_STRATEGY_HMPO_API_ENDPOINT_URL;

@ExtendWith(MockitoExtension.class)
class DvadAPIEndpointFactoryTest {

    private static final String TEST_ENDPOINT = "https://test-api.example.com";
    private static final String TEST_HEALTH_PATH = "/v1/health";
    private static final String TEST_TOKEN_PATH = "/v1/token";
    private static final String TEST_GRAPHQL_PATH = "/v1/graphql";

    @Mock private ParameterStoreService mockParameterStoreService;
    @Mock private CloseableHttpClient mockCloseableHttpClient;
    @Mock private RequestConfig mockRequestConfig;
    @Mock private EventProbe mockEventProbe;

    private ObjectMapper realObjectMapper;
    private DvadAPIEndpointFactory dvadAPIEndpointFactory;

    @BeforeEach
    void setUp() throws JsonProcessingException {
        realObjectMapper = new ObjectMapper();

        String endpointMapJson =
                String.format(
                        "{\"NO_CHANGE\":\"%s\",\"STUB\":\"https://stub-api.example.com\"}",
                        TEST_ENDPOINT);

        when(mockParameterStoreService.getParameterValue(HMPO_API_ENDPOINT_URL))
                .thenReturn(TEST_ENDPOINT);
        when(mockParameterStoreService.getParameterValue(TEST_STRATEGY_HMPO_API_ENDPOINT_URL))
                .thenReturn(endpointMapJson);
        when(mockParameterStoreService.getParameterValue(HMPO_API_ENDPOINT_HEALTH))
                .thenReturn(TEST_HEALTH_PATH);
        when(mockParameterStoreService.getParameterValue(HMPO_API_ENDPOINT_TOKEN))
                .thenReturn(TEST_TOKEN_PATH);
        when(mockParameterStoreService.getParameterValue(HMPO_API_ENDPOINT_GRAPHQL))
                .thenReturn(TEST_GRAPHQL_PATH);

        dvadAPIEndpointFactory = new DvadAPIEndpointFactory(mockParameterStoreService);
    }

    @Test
    void shouldInitialiseFieldsFromParameterStore() {
        assertEquals(TEST_ENDPOINT, dvadAPIEndpointFactory.hmpoEndPoint);
        assertEquals(TEST_HEALTH_PATH, dvadAPIEndpointFactory.healthPath);
        assertEquals(TEST_TOKEN_PATH, dvadAPIEndpointFactory.tokenPath);
        assertEquals(TEST_GRAPHQL_PATH, dvadAPIEndpointFactory.graphQLPath);
        assertEquals(TEST_ENDPOINT, dvadAPIEndpointFactory.hmpoEndPoints.get("NO_CHANGE"));
        assertEquals(
                "https://stub-api.example.com", dvadAPIEndpointFactory.hmpoEndPoints.get("STUB"));
    }

    @Test
    void shouldThrowJsonProcessingExceptionWhenEndpointUrlIsInvalidJson() {
        when(mockParameterStoreService.getParameterValue(TEST_STRATEGY_HMPO_API_ENDPOINT_URL))
                .thenReturn("not-valid-json");

        assertThrows(
                JsonProcessingException.class,
                () -> new DvadAPIEndpointFactory(mockParameterStoreService));
    }

    @Test
    void shouldCreateHealthCheckService() {
        HealthCheckService result =
                dvadAPIEndpointFactory.createHealthCheckService(
                        mockCloseableHttpClient,
                        mockRequestConfig,
                        realObjectMapper,
                        mockEventProbe,
                        Strategy.NO_CHANGE);

        assertNotNull(result);
    }

    @Test
    void shouldCreateTokenRequestService() {
        TokenRequestService result =
                dvadAPIEndpointFactory.createTokenRequestService(
                        mockCloseableHttpClient,
                        mockRequestConfig,
                        realObjectMapper,
                        mockEventProbe,
                        Strategy.NO_CHANGE);

        assertNotNull(result);
    }

    @Test
    void shouldCreateGraphQLRequestService() {
        GraphQLRequestService result =
                dvadAPIEndpointFactory.createGraphQLRequestService(
                        mockCloseableHttpClient,
                        mockRequestConfig,
                        realObjectMapper,
                        mockEventProbe,
                        Strategy.NO_CHANGE);

        assertNotNull(result);
    }

    @Test
    void shouldCreateServicesWithStubStrategy() {
        HealthCheckService healthCheckService =
                dvadAPIEndpointFactory.createHealthCheckService(
                        mockCloseableHttpClient,
                        mockRequestConfig,
                        realObjectMapper,
                        mockEventProbe,
                        Strategy.STUB);

        TokenRequestService tokenRequestService =
                dvadAPIEndpointFactory.createTokenRequestService(
                        mockCloseableHttpClient,
                        mockRequestConfig,
                        realObjectMapper,
                        mockEventProbe,
                        Strategy.STUB);

        GraphQLRequestService graphQLRequestService =
                dvadAPIEndpointFactory.createGraphQLRequestService(
                        mockCloseableHttpClient,
                        mockRequestConfig,
                        realObjectMapper,
                        mockEventProbe,
                        Strategy.STUB);

        assertNotNull(healthCheckService);
        assertNotNull(tokenRequestService);
        assertNotNull(graphQLRequestService);
    }

    @Test
    void shouldConstructParameterMapFromValidJson() throws JsonProcessingException {
        String json = "{\"key1\":\"value1\",\"key2\":\"value2\"}";

        Map<String, String> result = dvadAPIEndpointFactory.constructParameterMap(json);

        assertEquals(2, result.size());
        assertEquals("value1", result.get("key1"));
        assertEquals("value2", result.get("key2"));
    }

    @Test
    void shouldThrowJsonProcessingExceptionForInvalidParameterMapJson() {
        assertThrows(
                JsonProcessingException.class,
                () -> dvadAPIEndpointFactory.constructParameterMap("invalid-json"));
    }
}
