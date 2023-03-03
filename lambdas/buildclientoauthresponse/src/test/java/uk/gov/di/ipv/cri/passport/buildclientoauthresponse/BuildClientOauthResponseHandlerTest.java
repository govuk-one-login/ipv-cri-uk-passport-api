package uk.gov.di.ipv.cri.passport.buildclientoauthresponse;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventUser;
import uk.gov.di.ipv.cri.passport.library.config.PassportConfigurationService;
import uk.gov.di.ipv.cri.passport.library.domain.AuthParams;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.SqsException;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportSessionItem;
import uk.gov.di.ipv.cri.passport.library.service.AuditService;
import uk.gov.di.ipv.cri.passport.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.library.service.PassportSessionService;

import java.net.URISyntaxException;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_BUILD_CLIENT_OAUTH_RESPONSE_COMPLETED_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_BUILD_CLIENT_OAUTH_RESPONSE_COMPLETED_OK;

@ExtendWith(MockitoExtension.class)
class BuildClientOauthResponseHandlerTest {
    private static final String PASSPORT_SESSION_ID_HEADER_NAME = "session_id";
    private static final Map<String, String> TEST_EVENT_HEADERS =
            Map.of(PASSPORT_SESSION_ID_HEADER_NAME, "12345");
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_GOVUK_SIGNIN_JOURNEY_ID = "test-govuk-signin-journey-id";
    private static final String TEST_PASSPORT_SESSION_ID = "test-passport-session-id";

    private static final String TEST_RESPONSE_TYPE = "code";
    private static final String TEST_CLIENT_ID = "test_client_id";
    private static final String TEST_STATE = "test-state";
    private static final String TEST_REDIRECT_URI = "https://example.com";

    @Mock private Context context;
    @Mock private AuthorizationCodeService mockAuthorizationCodeService;
    @Mock private PassportSessionService mockPassportSessionService;
    @Mock private PassportConfigurationService mockPassportConfigurationService;
    @Mock private AuditService mockAuditService;
    @Mock private EventProbe mockEventProbe;

    private AuthorizationCode authorizationCode;
    private BuildClientOauthResponseHandler handler;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        authorizationCode = new AuthorizationCode();
        handler =
                new BuildClientOauthResponseHandler(
                        mockAuthorizationCodeService,
                        mockPassportSessionService,
                        mockAuditService,
                        mockPassportConfigurationService,
                        mockEventProbe);
    }

    @Test
    void shouldReturn200OnSuccessfulRequest()
            throws JsonProcessingException, SqsException, URISyntaxException {
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);
        when(mockPassportSessionService.getPassportSession(anyString()))
                .thenReturn(generatePassportSessionItem());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);
        assertNotNull(response.getBody());

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        JsonNode node = objectMapper.readTree(response.getBody());

        verify(mockEventProbe).counterMetric(LAMBDA_BUILD_CLIENT_OAUTH_RESPONSE_COMPLETED_OK);

        verify(mockAuthorizationCodeService)
                .persistAuthorizationCode(
                        authorizationCode.getValue(),
                        TEST_EVENT_HEADERS.get(PASSPORT_SESSION_ID_HEADER_NAME));

        verify(mockAuditService)
                .sendAuditEvent(
                        AuditEventTypes.IPV_PASSPORT_CRI_END,
                        new AuditEventUser(
                                TEST_USER_ID,
                                TEST_PASSPORT_SESSION_ID,
                                TEST_GOVUK_SIGNIN_JOURNEY_ID));

        String expectedRedirectUrl =
                new URIBuilder("https://example.com")
                        .addParameter("response_type", TEST_RESPONSE_TYPE)
                        .addParameter("code", authorizationCode.getValue())
                        .addParameter("state", TEST_STATE)
                        .addParameter("client_id", TEST_CLIENT_ID)
                        .build()
                        .toString();

        assertEquals(expectedRedirectUrl, node.get("redirectionURI").textValue());
        assertEquals(TEST_STATE, node.get("state").get("value").textValue());
        assertEquals(
                authorizationCode.getValue(),
                node.get("authorizationCode").get("value").textValue());
    }

    @Test
    void shouldReturn400WhenPassportSessionIdHeaderIsMissing() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        verify(mockEventProbe).counterMetric(LAMBDA_BUILD_CLIENT_OAUTH_RESPONSE_COMPLETED_ERROR);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.MISSING_PASSPORT_SESSION_ID_HEADER.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_PASSPORT_SESSION_ID_HEADER.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn500IfAuditServiceFails() throws SqsException, JsonProcessingException {
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);
        when(mockPassportSessionService.getPassportSession(anyString()))
                .thenReturn(generatePassportSessionItem());
        doThrow(new SqsException("Test error"))
                .when(mockAuditService)
                .sendAuditEvent(
                        eq(AuditEventTypes.IPV_PASSPORT_CRI_END), any(AuditEventUser.class));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        verify(mockEventProbe).counterMetric(LAMBDA_BUILD_CLIENT_OAUTH_RESPONSE_COMPLETED_ERROR);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.SERVER_ERROR.getCode(), responseBody.get("error"));
        assertEquals("Test error", responseBody.get("error_description"));
    }

    @Test
    void shouldReturn500OnInvalidUriStringForRedirectUri() throws JsonProcessingException {
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);
        PassportSessionItem passportSessionItem = generatePassportSessionItem();
        passportSessionItem.getAuthParams().setRedirectUri("https://inv^alid.com");
        when(mockPassportSessionService.getPassportSession(anyString()))
                .thenReturn(passportSessionItem);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        verify(mockEventProbe).counterMetric(LAMBDA_BUILD_CLIENT_OAUTH_RESPONSE_COMPLETED_ERROR);

        objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
    }

    @Test
    void shouldReturn403IfNoPassportAttemptHasBeenMade() throws JsonProcessingException {
        PassportSessionItem passportSessionItem = generatePassportSessionItem();
        passportSessionItem.setAttemptCount(0);
        when(mockPassportSessionService.getPassportSession(anyString()))
                .thenReturn(passportSessionItem);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        verify(mockEventProbe).counterMetric(LAMBDA_BUILD_CLIENT_OAUTH_RESPONSE_COMPLETED_OK);

        JsonNode responseBody = objectMapper.readTree(response.getBody());

        assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        JsonNode oauthError = responseBody.get("oauth_error");
        assertNotNull(oauthError);
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), oauthError.get("error").asText());
        assertEquals(
                "No passport details attempt has been made",
                oauthError.get("error_description").asText());
    }

    private PassportSessionItem generatePassportSessionItem() {
        PassportSessionItem item = new PassportSessionItem();

        AuthParams authParams =
                new AuthParams(TEST_RESPONSE_TYPE, TEST_CLIENT_ID, TEST_STATE, TEST_REDIRECT_URI);

        item.setAuthParams(authParams);
        item.setPassportSessionId(TEST_PASSPORT_SESSION_ID);
        item.setGovukSigninJourneyId(TEST_GOVUK_SIGNIN_JOURNEY_ID);
        item.setCreationDateTime(new Date().toString());
        item.setUserId(TEST_USER_ID);
        item.setAttemptCount(1);

        return item;
    }
}
