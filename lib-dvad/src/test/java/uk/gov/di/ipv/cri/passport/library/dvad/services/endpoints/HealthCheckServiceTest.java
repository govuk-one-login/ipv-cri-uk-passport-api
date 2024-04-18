package uk.gov.di.ipv.cri.passport.library.dvad.services.endpoints;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters;
import uk.gov.di.ipv.cri.passport.library.dvad.services.DvadAPIHeaderValues;
import uk.gov.di.ipv.cri.passport.library.dvad.util.responses.DVADResponseFixtures;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_REQUEST_CREATED;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_REQUEST_SEND_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_REQUEST_SEND_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_RESPONSE_LATENCY;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_RESPONSE_STATUS_DOWN;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_RESPONSE_STATUS_UP;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_RESPONSE_TYPE_EXPECTED_HTTP_STATUS;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_RESPONSE_TYPE_INVALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_RESPONSE_TYPE_VALID;

@ExtendWith(MockitoExtension.class)
class HealthCheckServiceTest {

    private final String TEST_END_POINT = "http://127.0.0.1";
    @Mock private CloseableHttpClient mockCloseableHttpClient;
    @Mock private RequestConfig mockRequestConfig;
    private ObjectMapper realObjectMapper;
    @Mock private EventProbe mockEventProbe;

    private HealthCheckService healthCheckService;

    @Mock ParameterStoreService mockParameterStoreService;

    private DvadAPIHeaderValues realDvadAPIHeaderValues;

    @BeforeEach
    void setUp() {
        realObjectMapper = new ObjectMapper();

        healthCheckService =
                new HealthCheckService(
                        TEST_END_POINT,
                        mockCloseableHttpClient,
                        mockRequestConfig,
                        realObjectMapper,
                        mockEventProbe);

        // Mock Parameter store fetches in DvadAPIHeaderValues
        Map<String, String> testParameterMap =
                Map.of(
                        "ApiKey",
                        "TEST_KEY",
                        "UserAgent",
                        "TEST_USER_AGENT",
                        "NetworkType",
                        "TEST_NETWORK_TYPE",
                        "ClientId",
                        "TEST_CLIENT_ID",
                        "Secret",
                        "TEST_SECRET",
                        "GrantType",
                        "TEST_GRANT_TYPE");

        when(mockParameterStoreService.getAllParametersFromPathWithDecryption(
                        ParameterStoreParameters.HMPO_API_HEADER_PARAMETER_PATH))
                .thenReturn(testParameterMap);

        realDvadAPIHeaderValues = new DvadAPIHeaderValues(mockParameterStoreService);
    }

    @ParameterizedTest
    @CsvSource({
        "true", // API UP
        "false", // API Down
    })
    void shouldReturnAPIStatusWhenHealthCheckReturnsStatusResponse(boolean apiStatus)
            throws OAuthErrorResponseException, IOException {

        ArgumentCaptor<HttpGet> httpRequestCaptor = ArgumentCaptor.forClass(HttpGet.class);

        // API UP/DOWN
        CloseableHttpResponse healthCheckResponse =
                DVADResponseFixtures.mockHealthCheckResponse(200, apiStatus, true);

        // HttpClient response
        when(mockCloseableHttpClient.execute(httpRequestCaptor.capture()))
                .thenReturn(healthCheckResponse);

        boolean apiIsUp = healthCheckService.checkRemoteApiIsUp(realDvadAPIHeaderValues);

        // (GET) Health, (POST) Token, (POST) GraphQL
        InOrder inOrderMockCloseableHttpClientSequence = inOrder(mockCloseableHttpClient);
        inOrderMockCloseableHttpClientSequence
                .verify(mockCloseableHttpClient, times(1))
                .execute(any(HttpGet.class));
        verifyNoMoreInteractions(mockCloseableHttpClient);

        InOrder inOrderMockEventProbeSequence = inOrder(mockEventProbe);
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_HEALTH_REQUEST_CREATED.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_HEALTH_REQUEST_SEND_OK.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(eq(DVAD_HEALTH_RESPONSE_LATENCY.withEndpointPrefix()), anyDouble());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_HEALTH_RESPONSE_TYPE_EXPECTED_HTTP_STATUS.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_HEALTH_RESPONSE_TYPE_VALID.withEndpointPrefix());
        if (apiStatus) {
            inOrderMockEventProbeSequence
                    .verify(mockEventProbe)
                    .counterMetric(DVAD_HEALTH_RESPONSE_STATUS_UP.withEndpointPrefix());
        } else {
            inOrderMockEventProbeSequence
                    .verify(mockEventProbe)
                    .counterMetric(DVAD_HEALTH_RESPONSE_STATUS_DOWN.withEndpointPrefix());
        }
        verifyNoMoreInteractions(mockEventProbe);

        assertEquals(apiStatus, apiIsUp);

        // Check Headers
        assertHealthHeaders(httpRequestCaptor);
    }

    @Test
    void shouldReturnFalseWhenHealthEndpointResponseStatusCodeNot200()
            throws IOException, OAuthErrorResponseException {

        ArgumentCaptor<HttpGet> httpRequestCaptor = ArgumentCaptor.forClass(HttpGet.class);

        // Status Code not 200
        CloseableHttpResponse healthCheckResponse =
                DVADResponseFixtures.mockHealthCheckResponse(500, true, true);

        // HttpClient response
        when(mockCloseableHttpClient.execute(httpRequestCaptor.capture()))
                .thenReturn(healthCheckResponse);

        String requestId = UUID.randomUUID().toString();

        boolean apiIsUp = healthCheckService.checkRemoteApiIsUp(realDvadAPIHeaderValues);

        // (GET) Health, (POST) Token, (POST) GraphQL
        InOrder inOrderMockCloseableHttpClientSequence = inOrder(mockCloseableHttpClient);
        inOrderMockCloseableHttpClientSequence
                .verify(mockCloseableHttpClient, times(1))
                .execute(any(HttpGet.class));
        verifyNoMoreInteractions(mockCloseableHttpClient);

        InOrder inOrderMockEventProbeSequence = inOrder(mockEventProbe);
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_HEALTH_REQUEST_CREATED.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_HEALTH_REQUEST_SEND_OK.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(eq(DVAD_HEALTH_RESPONSE_LATENCY.withEndpointPrefix()), anyDouble());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(
                        DVAD_HEALTH_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS.withEndpointPrefix());
        verifyNoMoreInteractions(mockEventProbe);

        assertFalse(apiIsUp);
        assertHealthHeaders(httpRequestCaptor);
    }

    @Test
    void shouldReturnOAuthErrorResponseExceptionWhenFailingToMapHealthEndpointResponse()
            throws IOException {
        ArgumentCaptor<HttpGet> httpRequestCaptor = ArgumentCaptor.forClass(HttpGet.class);

        // Invalid Response Body
        CloseableHttpResponse healthCheckResponse =
                DVADResponseFixtures.mockHealthCheckResponse(200, true, false);

        // HttpClient response
        when(mockCloseableHttpClient.execute(httpRequestCaptor.capture()))
                .thenReturn(healthCheckResponse);

        String requestId = UUID.randomUUID().toString();

        OAuthErrorResponseException expectedReturnedException =
                new OAuthErrorResponseException(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_MAP_HEALTH_ENDPOINT_RESPONSE_BODY);

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () -> healthCheckService.checkRemoteApiIsUp(realDvadAPIHeaderValues),
                        "Expected OAuthErrorResponseException");

        // (GET) Health
        InOrder inOrderMockCloseableHttpClientSequence = inOrder(mockCloseableHttpClient);
        inOrderMockCloseableHttpClientSequence
                .verify(mockCloseableHttpClient, times(1))
                .execute(any(HttpGet.class));
        verifyNoMoreInteractions(mockCloseableHttpClient);

        InOrder inOrderMockEventProbeSequence = inOrder(mockEventProbe);
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_HEALTH_REQUEST_CREATED.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_HEALTH_REQUEST_SEND_OK.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(eq(DVAD_HEALTH_RESPONSE_LATENCY.withEndpointPrefix()), anyDouble());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_HEALTH_RESPONSE_TYPE_EXPECTED_HTTP_STATUS.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_HEALTH_RESPONSE_TYPE_INVALID.withEndpointPrefix());
        verifyNoMoreInteractions(mockEventProbe);

        assertEquals(expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        assertEquals(expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
    }

    @Test
    void shouldReturnOAuthErrorResponseExceptionWhenHealthEndpointDoesNotRespond()
            throws IOException {
        String requestId = UUID.randomUUID().toString();

        Exception exceptionCaught = new IOException("Health Endpoint Timed out");

        doThrow(exceptionCaught).when(mockCloseableHttpClient).execute(any(HttpGet.class));

        OAuthErrorResponseException expectedReturnedException =
                new OAuthErrorResponseException(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.ERROR_INVOKING_THIRD_PARTY_API_HEALTH_ENDPOINT);

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () -> healthCheckService.checkRemoteApiIsUp(realDvadAPIHeaderValues),
                        "Expected OAuthErrorResponseException");

        // (GET) Health
        InOrder inOrderMockCloseableHttpClientSequence = inOrder(mockCloseableHttpClient);
        inOrderMockCloseableHttpClientSequence
                .verify(mockCloseableHttpClient, times(1))
                .execute(any(HttpGet.class));
        verifyNoMoreInteractions(mockCloseableHttpClient);

        InOrder inOrderMockEventProbeSequence = inOrder(mockEventProbe);
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_HEALTH_REQUEST_CREATED.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(eq(DVAD_HEALTH_RESPONSE_LATENCY.withEndpointPrefix()), anyDouble());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(
                        DVAD_HEALTH_REQUEST_SEND_ERROR.withEndpointPrefixAndExceptionName(
                                exceptionCaught));
        verifyNoMoreInteractions(mockEventProbe);

        assertEquals(expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        assertEquals(expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
    }

    private void assertHealthHeaders(ArgumentCaptor<HttpGet> httpRequestCaptor) {
        // Check Headers
        Map<String, String> httpHeadersKV =
                Arrays.stream(httpRequestCaptor.getValue().getAllHeaders())
                        .collect(Collectors.toMap(Header::getName, Header::getValue));

        assertNotNull(httpHeadersKV.get("X-REQUEST-ID"));
        assertDoesNotThrow(() -> UUID.fromString(httpHeadersKV.get("X-REQUEST-ID")));

        assertNotNull(httpHeadersKV.get("X-API-Key"));
        assertEquals("TEST_KEY", httpHeadersKV.get("X-API-Key"));

        assertNotNull(httpHeadersKV.get("User-Agent"));
        assertEquals("TEST_USER_AGENT", httpHeadersKV.get("User-Agent"));
    }
}
