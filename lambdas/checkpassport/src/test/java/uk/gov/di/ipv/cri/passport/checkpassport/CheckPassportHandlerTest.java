package uk.gov.di.ipv.cri.passport.checkpassport;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEvent;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventUser;
import uk.gov.di.ipv.cri.passport.library.config.PassportConfigurationService;
import uk.gov.di.ipv.cri.passport.library.domain.AuthParams;
import uk.gov.di.ipv.cri.passport.library.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.library.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.library.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.library.domain.responses.PassportSuccessResponse;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Evidence;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.EmptyDcsResponseException;
import uk.gov.di.ipv.cri.passport.library.exceptions.SqsException;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportSessionItem;
import uk.gov.di.ipv.cri.passport.library.service.AuditService;
import uk.gov.di.ipv.cri.passport.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.library.service.DcsCryptographyService;
import uk.gov.di.ipv.cri.passport.library.service.PassportService;
import uk.gov.di.ipv.cri.passport.library.service.PassportSessionService;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.MAXIMUM_ATTEMPT_COUNT;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.VERIFIABLE_CREDENTIAL_ISSUER;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.DCS_CHECK_REQUEST_SUCCEEDED;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.FORM_DATA_PARSE_PASS;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_RETRY;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_UNVERIFIED;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_COMPLETED_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_USER_REDIRECTED_ATTEMPTS_OVER_MAX;

@ExtendWith(MockitoExtension.class)
class CheckPassportHandlerTest {
    private static final String PASSPORT_SESSION_ID_HEADER_NAME = "session_id";
    public static final String PASSPORT_SESSION_ID = "test-session-id";

    public static final String TEST_USER_ID = "test-user-id";
    public static final String TEST_GOVUK_SIGNIN_JOURNEY_ID = "test-govuk-signin-journey-id";
    private static final Map<String, String> TEST_EVENT_HEADERS =
            Map.of(PASSPORT_SESSION_ID_HEADER_NAME, PASSPORT_SESSION_ID, "user_id", TEST_USER_ID);
    public static final String PASSPORT_NUMBER = "1234567890";
    public static final String SURNAME = "Tattsyrup";
    public static final List<String> FORENAMES = List.of("Tubbs");
    public static final String DATE_OF_BIRTH = "1984-09-28";
    public static final String EXPIRY_DATE = "2024-09-03";
    public static final Evidence VALID_PASSPORT_EVIDENCE =
            new Evidence(UUID.randomUUID().toString(), 4, 2, null);

    private static final int MAX_DOC_CHECK_ATTEMPTS = 2;

    private final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());
    private final Map<String, String> validPassportFormData =
            Map.of(
                    "passportNumber", PASSPORT_NUMBER,
                    "surname", SURNAME,
                    "forenames", FORENAMES.toString(),
                    "dateOfBirth", DATE_OF_BIRTH,
                    "expiryDate", EXPIRY_DATE);

    private final DcsResponse validDcsResponse =
            new DcsResponse(
                    UUID.randomUUID().toString(), UUID.randomUUID().toString(), false, true, null);

    private final DcsResponse invalidDcsResponse =
            new DcsResponse(
                    UUID.randomUUID().toString(), UUID.randomUUID().toString(), false, false, null);

    @Mock Context context;
    @Mock PassportService passportService;
    @Mock PassportConfigurationService mockPassportConfigurationService;
    @Mock DcsCryptographyService dcsCryptographyService;
    @Mock PassportSessionService passportSessionService;
    @Mock AuthorizationCodeService mockAuthorizationCodeService;
    @Mock AuditService mockAuditService;
    @Mock JWSObject jwsObject;
    @Mock EventProbe mockEventProbe;

    private AuthorizationCode authorizationCode;

    private CheckPassportHandler underTest;

    @BeforeEach
    void setUp() {
        authorizationCode = new AuthorizationCode();

        when(mockPassportConfigurationService.getSsmParameter(MAXIMUM_ATTEMPT_COUNT))
                .thenReturn(String.valueOf(MAX_DOC_CHECK_ATTEMPTS));

        underTest =
                new CheckPassportHandler(
                        passportService,
                        mockAuthorizationCodeService,
                        mockPassportConfigurationService,
                        dcsCryptographyService,
                        mockAuditService,
                        passportSessionService,
                        mockEventProbe);
    }

    @Test
    void shouldReturn200WithCorrectFormData()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException, SqsException {
        mockInitialSessionItem(0);
        mockIncrementAttemptCountSessionItem(1);
        mockDcsResponse(validDcsResponse);
        when(mockPassportConfigurationService.getSsmParameter(VERIFIABLE_CREDENTIAL_ISSUER))
                .thenReturn("test");
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "12345", objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        ArgumentCaptor<AuditEvent> argumentCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, times(2)).sendAuditEvent(argumentCaptor.capture());
        List<AuditEvent> capturedValues = argumentCaptor.getAllValues();
        assertEquals(
                AuditEventTypes.IPV_PASSPORT_CRI_REQUEST_SENT,
                capturedValues.get(0).getEventName());
        assertEquals(
                AuditEventTypes.IPV_PASSPORT_CRI_RESPONSE_RECEIVED,
                capturedValues.get(1).getEventName());

        verify(mockAuthorizationCodeService)
                .persistAuthorizationCode(
                        authorizationCode.getValue(),
                        TEST_EVENT_HEADERS.get(PASSPORT_SESSION_ID_HEADER_NAME));

        verify(mockAuditService)
                .sendAuditEvent(
                        AuditEventTypes.IPV_PASSPORT_CRI_END,
                        new AuditEventUser(
                                TEST_USER_ID, PASSPORT_SESSION_ID, TEST_GOVUK_SIGNIN_JOURNEY_ID));

        verify(mockEventProbe, times(1)).counterMetric(FORM_DATA_PARSE_PASS);
        verify(mockEventProbe, times(1)).counterMetric(DCS_CHECK_REQUEST_SUCCEEDED);
        verify(mockEventProbe, times(1)).counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_OK);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldPersistPassportCheckDao()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException {
        mockInitialSessionItem(0);
        mockIncrementAttemptCountSessionItem(1);
        mockDcsResponse(validDcsResponse);
        when(mockPassportConfigurationService.getSsmParameter(VERIFIABLE_CREDENTIAL_ISSUER))
                .thenReturn("test");
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "12345", objectMapper.writeValueAsString(validPassportFormData));

        underTest.handleRequest(event, context);

        ArgumentCaptor<PassportCheckDao> persistedPassportCheckDao =
                ArgumentCaptor.forClass(PassportCheckDao.class);

        verify(passportService).persistDcsResponse(persistedPassportCheckDao.capture());
        assertEquals(
                validPassportFormData.get("passportNumber"),
                persistedPassportCheckDao.getValue().getDcsPayload().getPassportNumber());
        assertEquals(
                VALID_PASSPORT_EVIDENCE.getStrengthScore(),
                persistedPassportCheckDao.getValue().getEvidence().getStrengthScore());
        assertEquals(
                VALID_PASSPORT_EVIDENCE.getValidityScore(),
                persistedPassportCheckDao.getValue().getEvidence().getValidityScore());
        assertNull(persistedPassportCheckDao.getValue().getEvidence().getCi());
    }

    @Test
    void shouldReturn200OnValidDCSResponseAndBelowAttemptCountLimit()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException, SqsException, URISyntaxException {
        mockInitialSessionItem(0);
        mockIncrementAttemptCountSessionItem(1);
        mockDcsResponse(validDcsResponse);
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);
        when(mockPassportConfigurationService.getSsmParameter(VERIFIABLE_CREDENTIAL_ISSUER))
                .thenReturn("test");

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "test-client-id", objectMapper.writeValueAsString(validPassportFormData));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(event, context);

        PassportSuccessResponse responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        ArgumentCaptor<AuditEvent> argumentCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, times(2)).sendAuditEvent(argumentCaptor.capture());
        List<AuditEvent> capturedValues = argumentCaptor.getAllValues();
        assertEquals(
                AuditEventTypes.IPV_PASSPORT_CRI_REQUEST_SENT,
                capturedValues.get(0).getEventName());
        assertEquals(
                AuditEventTypes.IPV_PASSPORT_CRI_RESPONSE_RECEIVED,
                capturedValues.get(1).getEventName());

        verify(mockAuthorizationCodeService)
                .persistAuthorizationCode(
                        authorizationCode.getValue(),
                        TEST_EVENT_HEADERS.get(PASSPORT_SESSION_ID_HEADER_NAME));

        verify(mockAuditService)
                .sendAuditEvent(
                        AuditEventTypes.IPV_PASSPORT_CRI_END,
                        new AuditEventUser(
                                TEST_USER_ID, PASSPORT_SESSION_ID, TEST_GOVUK_SIGNIN_JOURNEY_ID));

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe, times(1)).counterMetric(FORM_DATA_PARSE_PASS);
        inOrder.verify(mockEventProbe, times(1)).counterMetric(DCS_CHECK_REQUEST_SUCCEEDED);
        inOrder.verify(mockEventProbe, times(1)).counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_OK);

        assertEquals("https://example.com", responseBody.getRedirectURI());
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnRetryOnInvalidDCSResponseAndBelowAttemptCountLimit()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException {
        mockInitialSessionItem(0);
        mockIncrementAttemptCountSessionItem(1);
        mockDcsResponse(invalidDcsResponse);
        when(mockPassportConfigurationService.getSsmParameter(VERIFIABLE_CREDENTIAL_ISSUER))
                .thenReturn("test");

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "test-client-id", objectMapper.writeValueAsString(validPassportFormData));

        Map<String, Object> responseBody = getResponseBody(underTest.handleRequest(event, context));

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe, times(1)).counterMetric(FORM_DATA_PARSE_PASS);
        inOrder.verify(mockEventProbe, times(1)).counterMetric(DCS_CHECK_REQUEST_SUCCEEDED);
        inOrder.verify(mockEventProbe, times(1))
                .counterMetric(LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_RETRY);
        inOrder.verify(mockEventProbe, times(1)).counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_OK);

        assertEquals("retry", responseBody.get("result"));
    }

    @Test
    void shouldReturn200OnInvalidDCSResponseAndAttemptCountLimitReached()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException {
        mockInitialSessionItem(1);
        mockIncrementAttemptCountSessionItem(MAX_DOC_CHECK_ATTEMPTS);
        mockDcsResponse(invalidDcsResponse);
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);
        when(mockPassportConfigurationService.getSsmParameter(VERIFIABLE_CREDENTIAL_ISSUER))
                .thenReturn("test");

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "test-client-id", objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe, times(1)).counterMetric(FORM_DATA_PARSE_PASS);
        inOrder.verify(mockEventProbe, times(1)).counterMetric(DCS_CHECK_REQUEST_SUCCEEDED);
        inOrder.verify(mockEventProbe, times(1))
                .counterMetric(LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_UNVERIFIED);
        inOrder.verify(mockEventProbe, times(1)).counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_OK);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturn200IfAttemptMadeAfterAttemptCountLimitAlreadyReached() throws IOException {
        mockInitialSessionItem(MAX_DOC_CHECK_ATTEMPTS);
        mockIncrementAttemptCountSessionItem(
                MAX_DOC_CHECK_ATTEMPTS + 1); // new attempt is over the max

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "test-client-id", objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        // No form data is processed and no new check is made, instead the user is redirected
        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe, never()).counterMetric(FORM_DATA_PARSE_PASS);
        inOrder.verify(mockEventProbe, never()).counterMetric(DCS_CHECK_REQUEST_SUCCEEDED);
        inOrder.verify(mockEventProbe, times(1))
                .counterMetric(LAMBDA_CHECK_PASSPORT_USER_REDIRECTED_ATTEMPTS_OVER_MAX);
        inOrder.verify(mockEventProbe, times(1)).counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_OK);
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturn400IfPassportSessionIdMissing() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(new HashMap<>());
        Map<String, String> missingSessionHeaders = new HashMap<>(TEST_EVENT_HEADERS);
        missingSessionHeaders.remove(PASSPORT_SESSION_ID_HEADER_NAME);
        event.setHeaders(missingSessionHeaders);

        var response = underTest.handleRequest(event, context);
        Map<String, Object> responseBody = getResponseBody(response);

        verify(mockEventProbe).counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);

        assertEquals(
                ErrorResponse.MISSING_PASSPORT_SESSION_ID_HEADER.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_PASSPORT_SESSION_ID_HEADER.getMessage(),
                responseBody.get("message"));

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
    }

    @Test
    void shouldReturn400IfPassportSessionItemIsNotFound() throws Exception {
        when(passportSessionService.getPassportSession(PASSPORT_SESSION_ID)).thenReturn(null);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(new HashMap<>());
        Map<String, String> missingSessionHeaders = new HashMap<>(TEST_EVENT_HEADERS);
        event.setHeaders(missingSessionHeaders);

        Map<String, Object> responseBody = getResponseBody(underTest.handleRequest(event, context));

        verify(mockEventProbe).counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);

        assertEquals(
                ErrorResponse.PASSPORT_SESSION_NOT_FOUND.getMessage(),
                responseBody.get("error_description"));
    }

    @Test
    void shouldReturn400OAuthErrorIfDataIsMissing() throws JsonProcessingException {
        mockInitialSessionItem(0);
        mockIncrementAttemptCountSessionItem(1);

        var formFields = validPassportFormData.keySet();
        for (String keyToRemove : formFields) {
            APIGatewayProxyRequestEvent event =
                    getApiGatewayProxyRequestEvent(
                            "12345",
                            objectMapper.writeValueAsString(
                                    new HashMap<>(validPassportFormData).remove(keyToRemove)));

            var response = underTest.handleRequest(event, context);
            var responseBody = getResponseBody(response);

            assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
            assertEquals(OAuth2Error.SERVER_ERROR_CODE, responseBody.get("error"));
            assertEquals(
                    ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA.getMessage(),
                    responseBody.get("error_description"));
        }

        verify(mockEventProbe, times(formFields.size()))
                .counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);
    }

    @Test
    void shouldReturn400OAuthErrorIfDateStringsAreWrongFormat() throws JsonProcessingException {

        mockInitialSessionItem(0);
        mockIncrementAttemptCountSessionItem(1);

        var mangledDateInput = new HashMap<>(validPassportFormData);
        mangledDateInput.put("dateOfBirth", "28-09-1984");

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "12345", objectMapper.writeValueAsString(mangledDateInput));

        var response = underTest.handleRequest(event, context);
        var responseBody = getResponseBody(response);

        verify(mockEventProbe).counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.SERVER_ERROR_CODE, responseBody.get("error"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA.getMessage(),
                responseBody.get("error_description"));
    }

    @Test
    void shouldReturn500OAuthErrorOnDcsErrorResponse() throws Exception {
        mockInitialSessionItem(0);
        mockIncrementAttemptCountSessionItem(1);

        DcsSignedEncryptedResponse dcsSignedEncryptedResponse =
                new DcsSignedEncryptedResponse("TEST_PAYLOAD");
        when(passportService.dcsPassportCheck(any(JWSObject.class)))
                .thenReturn(dcsSignedEncryptedResponse);
        when(dcsCryptographyService.preparePayload(any(DcsPayload.class))).thenReturn(jwsObject);

        DcsResponse errorDcsResponse =
                new DcsResponse(
                        UUID.randomUUID().toString(),
                        UUID.randomUUID().toString(),
                        true,
                        false,
                        List.of("Test DCS error message"));
        when(dcsCryptographyService.unwrapDcsResponse(any(DcsSignedEncryptedResponse.class)))
                .thenReturn(errorDcsResponse);

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "12345", objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);
        var responseBody = getResponseBody(response);

        verify(mockEventProbe).counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(OAuth2Error.SERVER_ERROR_CODE, responseBody.get("error"));
        assertEquals(
                ErrorResponse.DCS_RETURNED_AN_ERROR.getMessage(),
                responseBody.get("error_description"));
    }

    private APIGatewayProxyRequestEvent getApiGatewayProxyRequestEvent(
            String clientId, String body) {
        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "https://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, clientId);
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setHeaders(TEST_EVENT_HEADERS);
        event.setBody(body);
        return event;
    }

    private Map<String, Object> getResponseBody(APIGatewayProxyResponseEvent response)
            throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(response.getBody(), new TypeReference<>() {});
    }

    private void mockDcsResponse(DcsResponse validDcsResponse)
            throws IOException, EmptyDcsResponseException, CertificateException,
                    NoSuchAlgorithmException, InvalidKeySpecException, JOSEException,
                    ParseException {
        DcsSignedEncryptedResponse dcsSignedEncryptedResponse =
                new DcsSignedEncryptedResponse("TEST_PAYLOAD");
        when(passportService.dcsPassportCheck(any(JWSObject.class)))
                .thenReturn(dcsSignedEncryptedResponse);
        when(dcsCryptographyService.preparePayload(any(DcsPayload.class))).thenReturn(jwsObject);
        when(dcsCryptographyService.unwrapDcsResponse(any(DcsSignedEncryptedResponse.class)))
                .thenReturn(validDcsResponse);
    }

    private PassportSessionItem createPassportSessionItem(int attemptCount) {
        PassportSessionItem passportSessionItem = new PassportSessionItem();
        passportSessionItem.setAttemptCount(attemptCount);
        passportSessionItem.setUserId(TEST_USER_ID);
        passportSessionItem.setPassportSessionId(PASSPORT_SESSION_ID);
        passportSessionItem.setGovukSigninJourneyId(TEST_GOVUK_SIGNIN_JOURNEY_ID);
        passportSessionItem.setAuthParams(
                new AuthParams("code", "12345", "test-state", "https://example.com"));

        return passportSessionItem;
    }

    private void mockInitialSessionItem(int attemptCount) {
        when(passportSessionService.getPassportSession(PASSPORT_SESSION_ID))
                .thenReturn(createPassportSessionItem(attemptCount));
    }

    private void mockIncrementAttemptCountSessionItem(int attemptCount) {
        when(passportSessionService.incrementAttemptCount(PASSPORT_SESSION_ID))
                .thenReturn(createPassportSessionItem(attemptCount));
    }
}
