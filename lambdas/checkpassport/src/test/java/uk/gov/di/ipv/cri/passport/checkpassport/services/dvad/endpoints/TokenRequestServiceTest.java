package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.AccessTokenResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.DvadAPIHeaderValues;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.util.dvad.responses.DVADResponseFixtures;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;

import java.io.IOException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_REQUEST_CREATED;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_REQUEST_SEND_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_REQUEST_SEND_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_EXPECTED_HTTP_STATUS;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_INVALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS;

@ExtendWith(MockitoExtension.class)
class TokenRequestServiceTest {

    private static final String TEST_END_POINT = "http://127.0.0.1";
    private static final String TEST_TOKEN_TYPE = "Bearer";
    private static final long TEST_TOKEN_EXPIRES_IN = 1800L;

    @Mock private RequestConfig mockRequestConfig;
    @Mock private CloseableHttpClient mockCloseableHttpClient;
    private ObjectMapper realObjectMapper;
    @Mock private EventProbe mockEventProbe;

    private TokenRequestService tokenRequestService;

    @Mock PassportConfigurationService mockPassportConfigurationService;

    private DvadAPIHeaderValues realDvadAPIHeaderValues;

    @BeforeEach
    void setUp() {
        realObjectMapper = new ObjectMapper();

        tokenRequestService =
                new TokenRequestService(
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

    @Test
    void shouldReturnAccessTokenResponseWhenTokenEndpointRespondsWithToken()
            throws OAuthErrorResponseException, IOException {

        ArgumentCaptor<HttpEntityEnclosingRequestBase> httpRequestCaptor =
                ArgumentCaptor.forClass(HttpPost.class);

        // Bearer access token
        CloseableHttpResponse tokenResponse =
                DVADResponseFixtures.mockTokenResponse(200, "Bearer", 1800, true);

        // HttpClient response
        when(mockCloseableHttpClient.execute(httpRequestCaptor.capture()))
                .thenReturn(tokenResponse);

        String requestId = UUID.randomUUID().toString();

        AccessTokenResponse accessTokenResponse =
                tokenRequestService.requestAccessToken(requestId, realDvadAPIHeaderValues);

        // (POST) Token
        InOrder inOrderMockCloseableHttpClientSequence = inOrder(mockCloseableHttpClient);
        inOrderMockCloseableHttpClientSequence
                .verify(mockCloseableHttpClient, times(1))
                .execute(any(HttpPost.class));
        verifyNoMoreInteractions(mockCloseableHttpClient);

        InOrder inOrderMockEventProbeSequence = inOrder(mockEventProbe);
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_TOKEN_REQUEST_CREATED.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_TOKEN_REQUEST_SEND_OK.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_TOKEN_RESPONSE_TYPE_EXPECTED_HTTP_STATUS.withEndpointPrefix());
        // Token Validity is checked later
        verifyNoMoreInteractions(mockEventProbe);

        assertNotNull(accessTokenResponse);
        assertEquals(TEST_TOKEN_TYPE, accessTokenResponse.getTokenType());
        assertEquals(TEST_TOKEN_EXPIRES_IN, accessTokenResponse.getExpiresIn());
    }

    @Test
    void shouldReturnOAuthErrorResponseExceptionWhenTokenEndpointDoesNotRespond()
            throws IOException {
        String requestId = UUID.randomUUID().toString();

        Exception exceptionCaught = new IOException("Token Endpoint Timed out");

        doThrow(exceptionCaught).when(mockCloseableHttpClient).execute(any(HttpPost.class));

        OAuthErrorResponseException expectedReturnedException =
                new OAuthErrorResponseException(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.ERROR_INVOKING_THIRD_PARTY_API_TOKEN_ENDPOINT);

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () ->
                                tokenRequestService.requestAccessToken(
                                        requestId, realDvadAPIHeaderValues),
                        "Expected OAuthErrorResponseException");

        // (Post) Token
        InOrder inOrderMockCloseableHttpClientSequence = inOrder(mockCloseableHttpClient);
        inOrderMockCloseableHttpClientSequence
                .verify(mockCloseableHttpClient, times(1))
                .execute(any(HttpPost.class));
        verifyNoMoreInteractions(mockCloseableHttpClient);

        InOrder inOrderMockEventProbeSequence = inOrder(mockEventProbe);
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_TOKEN_REQUEST_CREATED.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(
                        DVAD_TOKEN_REQUEST_SEND_ERROR.withEndpointPrefixAndExceptionName(
                                exceptionCaught));
        verifyNoMoreInteractions(mockEventProbe);

        assertEquals(expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        assertEquals(expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
    }

    @Test
    void shouldReturnOAuthErrorResponseExceptionWhenTokenEndpointResponseStatusCodeNot200()
            throws IOException {
        ArgumentCaptor<HttpPost> httpRequestCaptor = ArgumentCaptor.forClass(HttpPost.class);

        // Bearer access token but status not 200
        CloseableHttpResponse tokenResponse =
                DVADResponseFixtures.mockTokenResponse(501, "Bearer", 1800, false);

        // HttpClient response
        when(mockCloseableHttpClient.execute(httpRequestCaptor.capture()))
                .thenReturn(tokenResponse);

        String requestId = UUID.randomUUID().toString();

        OAuthErrorResponseException expectedReturnedException =
                new OAuthErrorResponseException(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.ERROR_TOKEN_ENDPOINT_RETURNED_UNEXPECTED_HTTP_STATUS_CODE);

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () ->
                                tokenRequestService.requestAccessToken(
                                        requestId, realDvadAPIHeaderValues),
                        "Expected OAuthErrorResponseException");

        // (Post) Token
        InOrder inOrderMockCloseableHttpClientSequence = inOrder(mockCloseableHttpClient);
        inOrderMockCloseableHttpClientSequence
                .verify(mockCloseableHttpClient, times(1))
                .execute(any(HttpPost.class));
        verifyNoMoreInteractions(mockCloseableHttpClient);

        InOrder inOrderMockEventProbeSequence = inOrder(mockEventProbe);
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_TOKEN_REQUEST_CREATED.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_TOKEN_REQUEST_SEND_OK.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(
                        DVAD_TOKEN_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS.withEndpointPrefix());
        verifyNoMoreInteractions(mockEventProbe);

        assertEquals(expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        assertEquals(expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
    }

    @Test
    void shouldReturnOAuthErrorResponseExceptionWhenFailingToMapTokenEndpointResponse()
            throws IOException {
        ArgumentCaptor<HttpPost> httpRequestCaptor = ArgumentCaptor.forClass(HttpPost.class);

        // Invalid Response Body
        CloseableHttpResponse tokenResponse =
                DVADResponseFixtures.mockTokenResponse(200, "Bearer", 1800, false);

        // HttpClient response
        when(mockCloseableHttpClient.execute(httpRequestCaptor.capture()))
                .thenReturn(tokenResponse);

        String requestId = UUID.randomUUID().toString();

        OAuthErrorResponseException expectedReturnedException =
                new OAuthErrorResponseException(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_MAP_TOKEN_ENDPOINT_RESPONSE_BODY);

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () ->
                                tokenRequestService.requestAccessToken(
                                        requestId, realDvadAPIHeaderValues),
                        "Expected OAuthErrorResponseException");

        // (Post) Token
        InOrder inOrderMockCloseableHttpClientSequence = inOrder(mockCloseableHttpClient);
        inOrderMockCloseableHttpClientSequence
                .verify(mockCloseableHttpClient, times(1))
                .execute(any(HttpPost.class));
        verifyNoMoreInteractions(mockCloseableHttpClient);

        InOrder inOrderMockEventProbeSequence = inOrder(mockEventProbe);
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_TOKEN_REQUEST_CREATED.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_TOKEN_REQUEST_SEND_OK.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_TOKEN_RESPONSE_TYPE_EXPECTED_HTTP_STATUS.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_TOKEN_RESPONSE_TYPE_INVALID.withEndpointPrefix());
        verifyNoMoreInteractions(mockEventProbe);

        assertEquals(expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        assertEquals(expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
    }
}
