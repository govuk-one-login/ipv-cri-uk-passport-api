package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpPost;
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
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.AccessTokenResponse;
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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints.TokenRequestService.ACCESS_TOKEN_EXPIRATION_WINDOW_SECONDS;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_API_KEY;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_CLIENT_ID;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_GRANT_TYPE;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_NETWORK_TYPE;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_SECRET;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_USER_AGENT;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_REQUEST_CREATED;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_REQUEST_REUSING_CACHED_TOKEN;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_REQUEST_SEND_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_REQUEST_SEND_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_EXPECTED_HTTP_STATUS;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_INVALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_VALID;

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
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_NETWORK_TYPE))
                .thenReturn("TEST_NETWORK_TYPE");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_CLIENT_ID))
                .thenReturn("TEST_CLIENT_ID");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_SECRET))
                .thenReturn("TEST_SECRET");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_GRANT_TYPE))
                .thenReturn("TEST_GRANT_TYPE");

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
                tokenRequestService.requestAccessToken(realDvadAPIHeaderValues, true);

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
        inOrderMockEventProbeSequence
                .verify(mockEventProbe)
                .counterMetric(DVAD_TOKEN_RESPONSE_TYPE_VALID.withEndpointPrefix());
        verifyNoMoreInteractions(mockEventProbe);

        assertNotNull(accessTokenResponse);
        assertEquals(TEST_TOKEN_TYPE, accessTokenResponse.getTokenType());
        assertEquals(TEST_TOKEN_EXPIRES_IN, accessTokenResponse.getExpiresIn());

        // Check Headers
        assertTokenHeaders(httpRequestCaptor);
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
                        () -> tokenRequestService.requestAccessToken(realDvadAPIHeaderValues, true),
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
                        () -> tokenRequestService.requestAccessToken(realDvadAPIHeaderValues, true),
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
                        () -> tokenRequestService.requestAccessToken(realDvadAPIHeaderValues, true),
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

    @ParameterizedTest
    @CsvSource({
        // TokenType, expiresIn
        "BAD_TOKEN_TYPE, 1800", // Bad type
        "Bearer, 0", // expiry short
        "Bearer, 1801", // bad expiry long
    })
    void shouldReturnOAuthErrorResponseExceptionWhenTokenTypeIsInvalid(
            String tokenType, long expiresIn) throws IOException {

        ArgumentCaptor<HttpPost> httpRequestCaptor = ArgumentCaptor.forClass(HttpPost.class);

        CloseableHttpResponse tokenResponse =
                DVADResponseFixtures.mockTokenResponse(200, tokenType, expiresIn, true);

        // HttpClient response
        when(mockCloseableHttpClient.execute(httpRequestCaptor.capture()))
                .thenReturn(tokenResponse);

        String requestId = UUID.randomUUID().toString();

        OAuthErrorResponseException expectedReturnedException =
                new OAuthErrorResponseException(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_VERIFY_ACCESS_TOKEN);

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () -> tokenRequestService.requestAccessToken(realDvadAPIHeaderValues, true),
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

    @Test
    void shouldReturnCachedAccessTokenIfTokenNotExpired()
            throws IOException, OAuthErrorResponseException {

        ArgumentCaptor<HttpPost> httpRequestCaptor = ArgumentCaptor.forClass(HttpPost.class);

        // A new token
        CloseableHttpResponse tokenResponse =
                DVADResponseFixtures.mockTokenResponse(200, "Bearer", 1800, true);

        // HttpClient response
        when(mockCloseableHttpClient.execute(httpRequestCaptor.capture()))
                .thenReturn(tokenResponse);

        String requestId = UUID.randomUUID().toString();

        // Request one
        AccessTokenResponse accessTokenResponseOne =
                tokenRequestService.requestAccessToken(realDvadAPIHeaderValues, false);

        // Request two
        AccessTokenResponse accessTokenResponseTwo =
                tokenRequestService.requestAccessToken(realDvadAPIHeaderValues, false);

        assertEquals(
                accessTokenResponseOne.getAccessToken(), accessTokenResponseTwo.getAccessToken());

        // (Post) Token
        InOrder inOrderMockCloseableHttpClientSequence = inOrder(mockCloseableHttpClient);
        inOrderMockCloseableHttpClientSequence
                .verify(mockCloseableHttpClient, times(1))
                .execute(any(HttpPost.class));
        verifyNoMoreInteractions(mockCloseableHttpClient);

        // Times 1 here is more important - token is cached
        InOrder inOrderMockEventProbeSequence = inOrder(mockEventProbe);
        inOrderMockEventProbeSequence
                .verify(mockEventProbe, times(1))
                .counterMetric(DVAD_TOKEN_REQUEST_CREATED.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe, times(1))
                .counterMetric(DVAD_TOKEN_REQUEST_SEND_OK.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe, times(1))
                .counterMetric(DVAD_TOKEN_RESPONSE_TYPE_EXPECTED_HTTP_STATUS.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe, times(1))
                .counterMetric(DVAD_TOKEN_RESPONSE_TYPE_VALID.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe, times(1))
                .counterMetric(DVAD_TOKEN_REQUEST_REUSING_CACHED_TOKEN.withEndpointPrefix());
        verifyNoMoreInteractions(mockEventProbe);
    }

    @Test
    void shouldNewAccessTokenWhenCachedAccessTokenIsExpired()
            throws IOException, OAuthErrorResponseException {

        ArgumentCaptor<HttpPost> httpRequestCaptor = ArgumentCaptor.forClass(HttpPost.class);

        // A new token with expiry inside expiration window
        long token1ExpiresIn = ACCESS_TOKEN_EXPIRATION_WINDOW_SECONDS - 1;
        CloseableHttpResponse tokenResponse1 =
                DVADResponseFixtures.mockTokenResponse(200, "Bearer", token1ExpiresIn, true);
        // A new token
        CloseableHttpResponse tokenResponse2 =
                DVADResponseFixtures.mockTokenResponse(200, "Bearer", 1800, true);

        // HttpClient response
        when(mockCloseableHttpClient.execute(httpRequestCaptor.capture()))
                .thenReturn(tokenResponse1)
                .thenReturn(tokenResponse2);

        String requestId = UUID.randomUUID().toString();

        // Request one
        AccessTokenResponse accessTokenResponseOne =
                tokenRequestService.requestAccessToken(realDvadAPIHeaderValues, false);

        // Request two
        AccessTokenResponse accessTokenResponseTwo =
                tokenRequestService.requestAccessToken(realDvadAPIHeaderValues, false);

        assertNotEquals(
                accessTokenResponseOne.getAccessToken(), accessTokenResponseTwo.getAccessToken());

        // (Post) Token
        InOrder inOrderMockCloseableHttpClientSequence = inOrder(mockCloseableHttpClient);
        inOrderMockCloseableHttpClientSequence
                .verify(mockCloseableHttpClient, times(2))
                .execute(any(HttpPost.class));
        verifyNoMoreInteractions(mockCloseableHttpClient);

        // Times 1 here is more important - token is cached
        InOrder inOrderMockEventProbeSequence = inOrder(mockEventProbe);
        // Token One Sequence
        inOrderMockEventProbeSequence
                .verify(mockEventProbe, times(1))
                .counterMetric(DVAD_TOKEN_REQUEST_CREATED.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe, times(1))
                .counterMetric(DVAD_TOKEN_REQUEST_SEND_OK.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe, times(1))
                .counterMetric(DVAD_TOKEN_RESPONSE_TYPE_EXPECTED_HTTP_STATUS.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe, times(1))
                .counterMetric(DVAD_TOKEN_RESPONSE_TYPE_VALID.withEndpointPrefix());
        // Token Two Sequence
        inOrderMockEventProbeSequence
                .verify(mockEventProbe, times(1))
                .counterMetric(DVAD_TOKEN_REQUEST_CREATED.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe, times(1))
                .counterMetric(DVAD_TOKEN_REQUEST_SEND_OK.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe, times(1))
                .counterMetric(DVAD_TOKEN_RESPONSE_TYPE_EXPECTED_HTTP_STATUS.withEndpointPrefix());
        inOrderMockEventProbeSequence
                .verify(mockEventProbe, times(1))
                .counterMetric(DVAD_TOKEN_RESPONSE_TYPE_VALID.withEndpointPrefix());
        verifyNoMoreInteractions(mockEventProbe);
    }

    private void assertTokenHeaders(
            ArgumentCaptor<HttpEntityEnclosingRequestBase> httpRequestCaptor) {
        // Check Headers
        Map<String, String> httpHeadersKV =
                Arrays.stream(httpRequestCaptor.getValue().getAllHeaders())
                        .collect(Collectors.toMap(Header::getName, Header::getValue));

        assertNotNull(httpHeadersKV.get("Content-Type"));
        assertEquals("application/x-www-form-urlencoded", httpHeadersKV.get("Content-Type"));

        assertNotNull(httpHeadersKV.get("X-REQUEST-ID"));
        assertDoesNotThrow(() -> UUID.fromString(httpHeadersKV.get("X-REQUEST-ID")));

        assertNotNull(httpHeadersKV.get("X-API-Key"));
        assertEquals("TEST_KEY", httpHeadersKV.get("X-API-Key"));

        assertNotNull(httpHeadersKV.get("User-Agent"));
        assertEquals("TEST_USER_AGENT", httpHeadersKV.get("User-Agent"));

        assertNotNull(httpHeadersKV.get("X-DVAD-NETWORK-TYPE"));
        assertEquals("TEST_NETWORK_TYPE", httpHeadersKV.get("X-DVAD-NETWORK-TYPE"));
    }
}
