package uk.gov.di.ipv.cri.passport.checkpassport.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.cri.common.library.exception.SessionExpiredException;
import uk.gov.di.ipv.cri.common.library.exception.SessionNotFoundException;
import uk.gov.di.ipv.cri.common.library.persistence.DataStore;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.PersonIdentityService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.DocumentDataVerificationResult;
import uk.gov.di.ipv.cri.passport.checkpassport.exception.OAuthHttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.cri.passport.checkpassport.services.DocumentDataVerificationService;
import uk.gov.di.ipv.cri.passport.checkpassport.util.DocumentDataVerificationServiceResultDataGenerator;
import uk.gov.di.ipv.cri.passport.library.PassportFormTestDataGenerator;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.error.CommonExpressOAuthError;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.common.library.error.ErrorResponse.SESSION_EXPIRED;
import static uk.gov.di.ipv.cri.common.library.error.ErrorResponse.SESSION_NOT_FOUND;
import static uk.gov.di.ipv.cri.passport.checkpassport.handler.CheckPassportHandler.RESULT;
import static uk.gov.di.ipv.cri.passport.checkpassport.handler.CheckPassportHandler.RESULT_RETRY;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.MAXIMUM_ATTEMPT_COUNT;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.FORM_DATA_PARSE_FAIL;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.FORM_DATA_PARSE_PASS;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_RETRY;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_UNVERIFIED;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_VERIFIED_PREFIX;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_COMPLETED_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_USER_REDIRECTED_ATTEMPTS_OVER_MAX;

@ExtendWith(MockitoExtension.class)
class CheckPassportHandlerTest {
    @Mock private Context mockLambdaContext;

    @Mock private ServiceFactory mockServiceFactory;
    @Mock private PassportConfigurationService mockPassportConfigurationService;

    // CRI-Lib Common Services and objects
    @Mock private EventProbe mockEventProbe;
    @Mock private SessionService mockSessionService;
    @Mock private PersonIdentityService mockPersonIdentityService;

    // Passport Common Services and objects
    private final ObjectMapper realObjectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());

    // Check Passport only service
    @Mock private DataStore<DocumentCheckResultItem> mockDocumentCheckResultStore;
    @Mock private DocumentDataVerificationService mockDocumentDataVerificationService;

    private CheckPassportHandler checkPassportHandler;

    @BeforeEach
    void setup() {
        when(mockServiceFactory.getObjectMapper()).thenReturn(realObjectMapper);
        when(mockServiceFactory.getPassportConfigurationService())
                .thenReturn(mockPassportConfigurationService);
        when(mockServiceFactory.getEventProbe()).thenReturn(mockEventProbe);
        when(mockServiceFactory.getSessionService()).thenReturn(mockSessionService);
        when(mockServiceFactory.getPersonIdentityService()).thenReturn(mockPersonIdentityService);
        when(mockServiceFactory.getDocumentCheckResultStore())
                .thenReturn(mockDocumentCheckResultStore);
        when(mockServiceFactory.getDocumentCheckResultStore())
                .thenReturn(mockDocumentCheckResultStore);

        this.checkPassportHandler =
                new CheckPassportHandler(mockServiceFactory, mockDocumentDataVerificationService);
    }

    @Test
    void handleResponseShouldReturnOkResponseWhenValidInputProvided()
            throws JsonProcessingException, OAuthHttpResponseExceptionWithErrorBody {
        final String SESSION_ID = UUID.randomUUID().toString();
        final String STATE = UUID.randomUUID().toString();
        final String REDIRECT_URI = "https://example.com";
        final int ATTEMPT_NO = 0; // No previous attempt

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();
        String testRequestBody = realObjectMapper.writeValueAsString(passportFormData);

        DocumentDataVerificationResult testDocumentDataVerificationResult =
                DocumentDataVerificationServiceResultDataGenerator.generate(passportFormData);

        APIGatewayProxyRequestEvent mockRequestEvent =
                Mockito.mock(APIGatewayProxyRequestEvent.class);

        when(mockRequestEvent.getBody()).thenReturn(testRequestBody);
        Map<String, String> requestHeaders = Map.of("session_id", SESSION_ID);
        when(mockRequestEvent.getHeaders()).thenReturn(requestHeaders);

        final var sessionItem = new SessionItem();
        sessionItem.setSessionId(UUID.fromString(SESSION_ID));
        sessionItem.setState(STATE);
        sessionItem.setRedirectUri(URI.create(REDIRECT_URI));
        sessionItem.setAttemptCount(ATTEMPT_NO);
        when(mockSessionService.validateSessionId(SESSION_ID)).thenReturn(sessionItem);

        when(mockDocumentDataVerificationService.verifyData(
                        any(PassportFormData.class), eq(sessionItem), eq(requestHeaders)))
                .thenReturn(testDocumentDataVerificationResult);

        when(mockPassportConfigurationService.getParameterValue(MAXIMUM_ATTEMPT_COUNT))
                .thenReturn("2");

        when(mockLambdaContext.getFunctionName()).thenReturn("functionName");
        when(mockLambdaContext.getFunctionVersion()).thenReturn("1.0");
        APIGatewayProxyResponseEvent responseEvent =
                checkPassportHandler.handleRequest(mockRequestEvent, mockLambdaContext);

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe).counterMetric(FORM_DATA_PARSE_PASS);
        inOrder.verify(mockEventProbe)
                .counterMetric(LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_VERIFIED_PREFIX + 1);
        inOrder.verify(mockEventProbe).counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_OK);
        verifyNoMoreInteractions(mockEventProbe);

        JsonNode responseTreeRootNode = realObjectMapper.readTree(responseEvent.getBody());

        assertNotNull(responseEvent);
        assertEquals(200, responseEvent.getStatusCode());
        assertEquals(SESSION_ID, responseTreeRootNode.get("session_id").textValue());
        assertEquals(STATE, responseTreeRootNode.get("state").textValue());
        assertEquals(REDIRECT_URI, responseTreeRootNode.get("redirect_uri").textValue());
    }

    @ParameterizedTest
    @CsvSource({
        // Previous AttemptCount, document status after attempt,
        "0, false", // No previous attempts, document becomes NOT verified (Attempt 1)
        "0, true", // No previous attempts, document becomes verified     (Attempt 1)
        "1, false", // 1 previous attempts, document becomes NOT verified  (Attempt 2)
        "1, true", // 1 previous attempts, document becomes verified      (Attempt 2)
        "2, false", // 2 previous attempts, N/A -------------------------- (Attempt 3 does not
        // happen - recovery redirect)
        "2, true", // 2 previous attempts, N/A -------------------------- (Attempt 3 does not happen
        // - recovery redirect)
    })
    void handleResponseShouldReturnCorrectResponsesForAttemptAndVerifiedStatus(
            final int previousAttemptCount, boolean documentVerified)
            throws JsonProcessingException, OAuthHttpResponseExceptionWithErrorBody {
        final String SESSION_ID = UUID.randomUUID().toString();
        final String STATE = UUID.randomUUID().toString();
        final String REDIRECT_URI = "https://example.com";
        final int ATTEMPT_NO = previousAttemptCount; // Test Parameter
        final int MAX_ATTEMPTS = 2; //

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();
        String testRequestBody = realObjectMapper.writeValueAsString(passportFormData);

        DocumentDataVerificationResult testDocumentDataVerificationResult =
                DocumentDataVerificationServiceResultDataGenerator.generate(passportFormData);

        testDocumentDataVerificationResult.setVerified(documentVerified); // Test Parameter

        APIGatewayProxyRequestEvent mockRequestEvent =
                Mockito.mock(APIGatewayProxyRequestEvent.class);

        Map<String, String> requestHeaders = Map.of("session_id", SESSION_ID);
        when(mockRequestEvent.getHeaders()).thenReturn(requestHeaders);

        final var sessionItem = new SessionItem();
        sessionItem.setSessionId(UUID.fromString(SESSION_ID));
        sessionItem.setState(STATE);
        sessionItem.setRedirectUri(URI.create(REDIRECT_URI));
        sessionItem.setAttemptCount(ATTEMPT_NO);
        when(mockSessionService.validateSessionId(SESSION_ID)).thenReturn(sessionItem);

        // If max attempts is reached the user is redirected with no further attempts allowed
        // new attempt are allowed below max
        if (sessionItem.getAttemptCount() < MAX_ATTEMPTS) {
            // parsePassportFormRequest
            when(mockRequestEvent.getBody()).thenReturn(testRequestBody);
            when(mockDocumentDataVerificationService.verifyData(
                            any(PassportFormData.class), eq(sessionItem), eq(requestHeaders)))
                    .thenReturn(testDocumentDataVerificationResult);
        }

        when(mockPassportConfigurationService.getParameterValue(MAXIMUM_ATTEMPT_COUNT))
                .thenReturn(String.valueOf(MAX_ATTEMPTS));

        when(mockLambdaContext.getFunctionName()).thenReturn("functionName");
        when(mockLambdaContext.getFunctionVersion()).thenReturn("1.0");
        APIGatewayProxyResponseEvent responseEvent =
                checkPassportHandler.handleRequest(mockRequestEvent, mockLambdaContext);

        JsonNode responseTreeRootNode = realObjectMapper.readTree(responseEvent.getBody());

        InOrder inOrder = inOrder(mockEventProbe);
        assertNotNull(responseEvent);
        assertEquals(200, responseEvent.getStatusCode());

        if (sessionItem.getAttemptCount() <= MAX_ATTEMPTS && documentVerified) {
            // Where an attempt happens and the document is verified
            inOrder.verify(mockEventProbe).counterMetric(FORM_DATA_PARSE_PASS);
            inOrder.verify(mockEventProbe)
                    .counterMetric(
                            LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_VERIFIED_PREFIX
                                    + sessionItem.getAttemptCount());

            assertEquals(SESSION_ID, responseTreeRootNode.get("session_id").textValue());
            assertEquals(STATE, responseTreeRootNode.get("state").textValue());
            assertEquals(REDIRECT_URI, responseTreeRootNode.get("redirect_uri").textValue());
        } else if (sessionItem.getAttemptCount() < MAX_ATTEMPTS && !documentVerified) {
            // Any attempt below max attempts where the document is NOT verified
            inOrder.verify(mockEventProbe).counterMetric(FORM_DATA_PARSE_PASS);
            inOrder.verify(mockEventProbe)
                    .counterMetric(LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_RETRY);

            assertEquals(RESULT_RETRY, responseTreeRootNode.get(RESULT).textValue());
        } else if (sessionItem.getAttemptCount() == MAX_ATTEMPTS && !documentVerified) {
            // The last possible attempt reaches max attempts and the document is NOT verified
            inOrder.verify(mockEventProbe).counterMetric(FORM_DATA_PARSE_PASS);
            inOrder.verify(mockEventProbe)
                    .counterMetric(LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_UNVERIFIED);

            assertEquals(SESSION_ID, responseTreeRootNode.get("session_id").textValue());
            assertEquals(STATE, responseTreeRootNode.get("state").textValue());
            assertEquals(REDIRECT_URI, responseTreeRootNode.get("redirect_uri").textValue());
        } else {
            // A form is submitted but max attempts is already reached.
            // No form parsing, no attempt - user redirected
            inOrder.verify(mockEventProbe)
                    .counterMetric(LAMBDA_CHECK_PASSPORT_USER_REDIRECTED_ATTEMPTS_OVER_MAX);

            assertEquals(SESSION_ID, responseTreeRootNode.get("session_id").textValue());
            assertEquals(STATE, responseTreeRootNode.get("state").textValue());
            assertEquals(REDIRECT_URI, responseTreeRootNode.get("redirect_uri").textValue());
        }

        inOrder.verify(mockEventProbe).counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_OK);
        verifyNoMoreInteractions(mockEventProbe);
    }

    @ParameterizedTest
    @CsvSource({
        "SessionNotFoundException",
        "SessionExpiredException",
    })
    void handleResponseShouldReturn403whenSessionValidationFailsWithException(String exceptionType)
            throws JsonProcessingException {
        final String SESSION_ID = UUID.randomUUID().toString();
        final String STATE = UUID.randomUUID().toString();
        final String REDIRECT_URI = "https://example.com";

        APIGatewayProxyRequestEvent mockRequestEvent =
                Mockito.mock(APIGatewayProxyRequestEvent.class);

        Map<String, String> requestHeaders = Map.of("session_id", SESSION_ID);
        when(mockRequestEvent.getHeaders()).thenReturn(requestHeaders);

        final var sessionItem = new SessionItem();
        sessionItem.setSessionId(UUID.fromString(SESSION_ID));
        sessionItem.setState(STATE);
        sessionItem.setRedirectUri(URI.create(REDIRECT_URI));
        sessionItem.setAttemptCount(0);

        if (exceptionType.equals("SessionNotFoundException")) {
            when(mockSessionService.validateSessionId(SESSION_ID))
                    .thenThrow(new SessionNotFoundException("session not found"));
        } else {
            when(mockSessionService.validateSessionId(SESSION_ID))
                    .thenThrow(new SessionExpiredException("session expired"));
        }

        when(mockLambdaContext.getFunctionName()).thenReturn("functionName");
        when(mockLambdaContext.getFunctionVersion()).thenReturn("1.0");
        APIGatewayProxyResponseEvent responseEvent =
                checkPassportHandler.handleRequest(mockRequestEvent, mockLambdaContext);

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe).counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);
        verifyNoMoreInteractions(mockEventProbe);

        JsonNode responseTreeRootNode = realObjectMapper.readTree(responseEvent.getBody());
        JsonNode oauthErrorNode = responseTreeRootNode.get("oauth_error");

        CommonExpressOAuthError expectedObject;
        if (exceptionType.equals("SessionNotFoundException")) {
            expectedObject =
                    new CommonExpressOAuthError(
                            OAuth2Error.ACCESS_DENIED, SESSION_NOT_FOUND.getMessage());
        } else {
            expectedObject =
                    new CommonExpressOAuthError(
                            OAuth2Error.ACCESS_DENIED, SESSION_EXPIRED.getMessage());
        }

        assertNotNull(responseEvent);
        assertNotNull(responseTreeRootNode);
        assertNotNull(oauthErrorNode);
        assertEquals(HttpStatusCode.FORBIDDEN, responseEvent.getStatusCode());

        // Assert CommonExpress OAuth error format
        assertEquals(
                "oauth_error",
                responseTreeRootNode.fieldNames().next().toString()); // Root Node Name
        assertEquals(
                expectedObject.getError().get("error"),
                oauthErrorNode.get("error").textValue()); // error
        assertEquals(
                expectedObject.getError().get("error_description"),
                oauthErrorNode.get("error_description").textValue()); // error description
    }

    @Test
    void handleResponseShouldReturn400whenPassportFormDataCannotBeMappedFromBody()
            throws JsonProcessingException {
        final String SESSION_ID = UUID.randomUUID().toString();
        final String STATE = UUID.randomUUID().toString();
        final String REDIRECT_URI = "https://example.com";
        final int ATTEMPT_NO = 0;
        final int MAX_ATTEMPTS = 2;

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();

        // Invalid the data via removing all form fields from valid form data
        Map invalidatedFormDataAsMap = realObjectMapper.convertValue(passportFormData, Map.class);
        Object[] formFields = invalidatedFormDataAsMap.keySet().toArray();
        for (Object field : formFields) {
            invalidatedFormDataAsMap.remove(field);
        }

        String testRequestBody = realObjectMapper.writeValueAsString(invalidatedFormDataAsMap);

        APIGatewayProxyRequestEvent mockRequestEvent =
                Mockito.mock(APIGatewayProxyRequestEvent.class);

        Map<String, String> requestHeaders = Map.of("session_id", SESSION_ID);
        when(mockRequestEvent.getHeaders()).thenReturn(requestHeaders);

        final var sessionItem = new SessionItem();
        sessionItem.setSessionId(UUID.fromString(SESSION_ID));
        sessionItem.setState(STATE);
        sessionItem.setRedirectUri(URI.create(REDIRECT_URI));
        sessionItem.setAttemptCount(ATTEMPT_NO);
        when(mockSessionService.validateSessionId(SESSION_ID)).thenReturn(sessionItem);

        // parsePassportFormRequest
        when(mockRequestEvent.getBody()).thenReturn(testRequestBody);

        when(mockPassportConfigurationService.getParameterValue(MAXIMUM_ATTEMPT_COUNT))
                .thenReturn(String.valueOf(MAX_ATTEMPTS));

        when(mockLambdaContext.getFunctionName()).thenReturn("functionName");
        when(mockLambdaContext.getFunctionVersion()).thenReturn("1.0");

        APIGatewayProxyResponseEvent responseEvent =
                checkPassportHandler.handleRequest(mockRequestEvent, mockLambdaContext);

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe).counterMetric(FORM_DATA_PARSE_FAIL);
        inOrder.verify(mockEventProbe).counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);
        verifyNoMoreInteractions(mockEventProbe);

        JsonNode responseTreeRootNode = realObjectMapper.readTree(responseEvent.getBody());
        JsonNode oauthErrorNode = responseTreeRootNode.get("oauth_error");

        CommonExpressOAuthError expectedObject =
                new CommonExpressOAuthError(
                        OAuth2Error.SERVER_ERROR, OAuth2Error.SERVER_ERROR.getDescription());
        System.out.println(responseTreeRootNode);

        assertNotNull(responseEvent);
        assertNotNull(responseTreeRootNode);
        assertNotNull(oauthErrorNode);
        assertEquals(HttpStatusCode.BAD_REQUEST, responseEvent.getStatusCode());

        // Assert CommonExpress OAuth error format
        assertEquals(
                "oauth_error",
                responseTreeRootNode.fieldNames().next().toString()); // Root Node Name
        assertEquals(
                expectedObject.getError().get("error"),
                oauthErrorNode.get("error").textValue()); // error
        assertEquals(
                expectedObject.getError().get("error_description"),
                oauthErrorNode.get("error_description").textValue()); // error description
    }

    @Test
    void handleResponseShouldReturnServerErrorForUnhandledExceptions()
            throws JsonProcessingException, OAuthHttpResponseExceptionWithErrorBody {
        final String SESSION_ID = UUID.randomUUID().toString();
        final String STATE = UUID.randomUUID().toString();
        final String REDIRECT_URI = "https://example.com";
        final int ATTEMPT_NO = 0; // No previous attempt

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();
        String testRequestBody = realObjectMapper.writeValueAsString(passportFormData);

        APIGatewayProxyRequestEvent mockRequestEvent =
                Mockito.mock(APIGatewayProxyRequestEvent.class);

        when(mockRequestEvent.getBody()).thenReturn(testRequestBody);
        Map<String, String> requestHeaders = Map.of("session_id", SESSION_ID);
        when(mockRequestEvent.getHeaders()).thenReturn(requestHeaders);

        final var sessionItem = new SessionItem();
        sessionItem.setSessionId(UUID.fromString(SESSION_ID));
        sessionItem.setState(STATE);
        sessionItem.setRedirectUri(URI.create(REDIRECT_URI));
        sessionItem.setAttemptCount(ATTEMPT_NO);
        when(mockSessionService.validateSessionId(SESSION_ID)).thenReturn(sessionItem);

        when(mockDocumentDataVerificationService.verifyData(
                        any(PassportFormData.class), eq(sessionItem), eq(requestHeaders)))
                .thenThrow(new RuntimeException("An Unhandled exception that has occurred"));

        when(mockPassportConfigurationService.getParameterValue(MAXIMUM_ATTEMPT_COUNT))
                .thenReturn("2");

        when(mockLambdaContext.getFunctionName()).thenReturn("functionName");
        when(mockLambdaContext.getFunctionVersion()).thenReturn("1.0");
        APIGatewayProxyResponseEvent responseEvent =
                checkPassportHandler.handleRequest(mockRequestEvent, mockLambdaContext);

        JsonNode responseTreeRootNode = realObjectMapper.readTree(responseEvent.getBody());
        JsonNode oauthErrorNode = responseTreeRootNode.get("oauth_error");

        CommonExpressOAuthError expectedObject =
                new CommonExpressOAuthError(
                        OAuth2Error.SERVER_ERROR, OAuth2Error.SERVER_ERROR.getDescription());
        System.out.println(responseTreeRootNode);

        assertNotNull(responseEvent);
        assertNotNull(responseTreeRootNode);
        assertNotNull(oauthErrorNode);
        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, responseEvent.getStatusCode());

        // Assert CommonExpress OAuth error format
        assertEquals(
                "oauth_error",
                responseTreeRootNode.fieldNames().next().toString()); // Root Node Name
        assertEquals(
                expectedObject.getError().get("error"),
                oauthErrorNode.get("error").textValue()); // error
        assertEquals(
                expectedObject.getError().get("error_description"),
                oauthErrorNode.get("error_description").textValue()); // error description
    }
}
