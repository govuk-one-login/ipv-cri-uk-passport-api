package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints;

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
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.DvadAPIHeaderValues;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.util.dvad.responses.DVADResponseFixtures;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_API_KEY;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_AUDIENCE;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_CLIENT_ID;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_GRANT_TYPE;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_SECRET;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_USER_AGENT;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_REQUEST_CREATED;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_REQUEST_SEND_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_REQUEST_SEND_OK;
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

    @Mock PassportConfigurationService mockPassportConfigurationService;

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
        when(mockPassportConfigurationService.getEncryptedSsmParameter(HMPO_API_HEADER_API_KEY))
                .thenReturn("TEST_KEY");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_USER_AGENT))
                .thenReturn("TEST_USER_AGENT");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_CLIENT_ID))
                .thenReturn("TEST_CLIENT_ID");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_SECRET))
                .thenReturn("TEST_SECRET");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_GRANT_TYPE))
                .thenReturn("TEST_GRANT_TYPE");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_AUDIENCE))
                .thenReturn("TEST_AUDIENCE");

        realDvadAPIHeaderValues = new DvadAPIHeaderValues(mockPassportConfigurationService);
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

        String requestId = UUID.randomUUID().toString();

        boolean apiIsUp = healthCheckService.checkRemoteApiIsUp(requestId, realDvadAPIHeaderValues);

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
        assertHealthHeaders(requestId, httpRequestCaptor);
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

        boolean apiIsUp = healthCheckService.checkRemoteApiIsUp(requestId, realDvadAPIHeaderValues);

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
                .counterMetric(
                        DVAD_HEALTH_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS.withEndpointPrefix());
        verifyNoMoreInteractions(mockEventProbe);

        assertFalse(apiIsUp);
        assertHealthHeaders(requestId, httpRequestCaptor);
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
                        () ->
                                healthCheckService.checkRemoteApiIsUp(
                                        requestId, realDvadAPIHeaderValues),
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
                        () ->
                                healthCheckService.checkRemoteApiIsUp(
                                        requestId, realDvadAPIHeaderValues),
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
                .counterMetric(
                        DVAD_HEALTH_REQUEST_SEND_ERROR.withEndpointPrefixAndExceptionName(
                                exceptionCaught));
        verifyNoMoreInteractions(mockEventProbe);

        assertEquals(expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        assertEquals(expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
    }

    private void assertHealthHeaders(String requestId, ArgumentCaptor<HttpGet> httpRequestCaptor) {
        // Check Headers
        Map<String, String> httpHeadersKV =
                Arrays.stream(httpRequestCaptor.getValue().getAllHeaders())
                        .collect(Collectors.toMap(Header::getName, Header::getValue));

        assertNotNull(httpHeadersKV.get("X-Request-id"));
        assertEquals(requestId, httpHeadersKV.get("X-Request-id"));

        assertNotNull(httpHeadersKV.get("X-API-Key"));
        assertEquals("TEST_KEY", httpHeadersKV.get("X-API-Key"));

        assertNotNull(httpHeadersKV.get("User-Agent"));
        assertEquals("TEST_USER_AGENT", httpHeadersKV.get("User-Agent"));
    }
}
