package uk.gov.di.ipv.cri.passport.checkpassport.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.junit.jupiter.api.AfterEach;
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
import uk.gov.di.ipv.cri.passport.checkpassport.services.DocumentDataVerificationService;
import uk.gov.di.ipv.cri.passport.checkpassport.util.DocumentDataVerificationServiceResultDataGenerator;
import uk.gov.di.ipv.cri.passport.library.PassportFormTestDataGenerator;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.domain.Strategy;
import uk.gov.di.ipv.cri.passport.library.error.CommonExpressOAuthError;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;
import uk.gov.di.ipv.cri.passport.library.service.ApacheHTTPClientFactoryService;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;
import uk.gov.di.ipv.cri.passport.library.service.ThirdPartyAPIService;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.net.URI;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.common.library.error.ErrorResponse.SESSION_EXPIRED;
import static uk.gov.di.ipv.cri.common.library.error.ErrorResponse.SESSION_NOT_FOUND;
import static uk.gov.di.ipv.cri.passport.checkpassport.handler.CheckPassportHandler.RESULT;
import static uk.gov.di.ipv.cri.passport.checkpassport.handler.CheckPassportHandler.RESULT_RETRY;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DOCUMENT_CHECK_RESULT_TTL_PARAMETER;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.FORM_DATA_PARSE_FAIL;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.FORM_DATA_PARSE_PASS;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_RETRY;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_UNVERIFIED;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_VERIFIED_PREFIX;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_COMPLETED_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_FUNCTION_INIT_DURATION;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_USER_REDIRECTED_ATTEMPTS_OVER_MAX;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class CheckPassportHandlerTest {

    private final ObjectMapper realObjectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());

    private String testStrategyRawEndpointValue =
            """
            {
                "STUB": "http://localhostStub",
                "UAT": "http://localhostUat",
                "LIVE": "http://localhostLive"
            }
            """;
    @SystemStub private EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Mock private Context mockLambdaContext;

    // Returned via the ServiceFactory
    @Mock private EventProbe mockEventProbe;
    @Mock private ApacheHTTPClientFactoryService mockApacheHTTPClientFactoryService;
    @Mock private ParameterStoreService mockParameterStoreService;
    @Mock private SessionService mockSessionService;
    @Mock private PersonIdentityService mockPersonIdentityService;
    @Mock private DataStore<DocumentCheckResultItem> mockDocumentCheckResultStore;

    // Created in check passport
    @Mock private ServiceFactory mockServiceFactory;
    @Mock private DocumentDataVerificationService mockDocumentDataVerificationService;

    private CheckPassportHandler checkPassportHandler;

    @BeforeEach
    void setup() throws JsonProcessingException {
        environmentVariables.set("AWS_REGION", "eu-west-2");
        environmentVariables.set("AWS_STACK_NAME", "TEST_STACK");
        environmentVariables.set("DVAD_PERFORMANCE_STUB_IN_USE", "false");
        environmentVariables.set("DEV_ENVIRONMENT_ONLY_ENHANCED_DEBUG", "false");

        when(mockParameterStoreService.getParameterValue("HMPODVAD/API/EndpointUrl"))
                .thenReturn("http://localhost");

        when(mockParameterStoreService.getParameterValue(
                        "HMPODVAD/API/TestStrategy/EndpointUrl")) // pragma: allowlist secret
                .thenReturn(testStrategyRawEndpointValue);

        mockServiceFactoryBehaviour();

        checkPassportHandler =
                new CheckPassportHandler(mockServiceFactory, mockDocumentDataVerificationService);
    }

    @AfterEach
    public void tearDown() {
        verifyNoMoreInteractions(mockDocumentDataVerificationService);
    }

    @Test
    void handleResponseShouldReturnOkResponseWhenValidInputProvided()
            throws JsonProcessingException, OAuthErrorResponseException {
        final String SESSION_ID = UUID.randomUUID().toString();
        final String STATE = UUID.randomUUID().toString();
        final String REDIRECT_URI = "https://example.com";
        final int ATTEMPT_NO = 0; // No previous attempt

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();
        String testRequestBody = realObjectMapper.writeValueAsString(passportFormData);

        DocumentDataVerificationResult testDocumentDataVerificationResult =
                DocumentDataVerificationServiceResultDataGenerator.generate(passportFormData);
        testDocumentDataVerificationResult.setContraIndicators(new ArrayList<>());
        testDocumentDataVerificationResult.setChecksSucceeded(List.of("verification_check"));

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
        sessionItem.setClientId("testNoChangeId");
        when(mockSessionService.validateSessionId(SESSION_ID)).thenReturn(sessionItem);

        when(mockDocumentDataVerificationService.verifyData(
                        any(ThirdPartyAPIService.class),
                        any(PassportFormData.class),
                        eq(sessionItem),
                        eq(requestHeaders),
                        eq(Strategy.NO_CHANGE)))
                .thenReturn(testDocumentDataVerificationResult);

        when(mockParameterStoreService.getCommonParameterValue(DOCUMENT_CHECK_RESULT_TTL_PARAMETER))
                .thenReturn("7200");

        mockLambdaContext();

        APIGatewayProxyResponseEvent responseEvent =
                checkPassportHandler.handleRequest(mockRequestEvent, mockLambdaContext);

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe)
                .counterMetric(eq(LAMBDA_CHECK_PASSPORT_FUNCTION_INIT_DURATION), anyDouble());
        inOrder.verify(mockEventProbe).counterMetric(FORM_DATA_PARSE_PASS);
        inOrder.verify(mockEventProbe)
                .counterMetric(LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_VERIFIED_PREFIX + 1);
        inOrder.verify(mockEventProbe).counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_OK);
        verifyNoMoreInteractions(mockEventProbe);
        verify(mockDocumentDataVerificationService)
                .verifyData(
                        any(ThirdPartyAPIService.class),
                        eq(passportFormData),
                        any(SessionItem.class),
                        eq(requestHeaders),
                        eq(Strategy.NO_CHANGE));

        DocumentCheckResultItem documentCheckResultItem =
                mapDocumentDataVerificationResultToDocumentCheckResultItem(
                        sessionItem, testDocumentDataVerificationResult, passportFormData);
        verify(mockDocumentCheckResultStore).create(documentCheckResultItem);
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
        "2, false", // 2 previous attempts, N/A - (Attempt 3 does not happen - recovery redirect)
        "2, true", // 2 previous attempts, N/A - (Attempt 3 does not happen - recovery redirect)
    })
    void handleResponseShouldReturnCorrectResponsesForAttemptAndVerifiedStatus(
            final int previousAttemptCount, boolean documentVerified)
            throws JsonProcessingException, OAuthErrorResponseException {
        final String SESSION_ID = UUID.randomUUID().toString();
        final String STATE = UUID.randomUUID().toString();
        final String REDIRECT_URI = "https://example.com";
        final int ATTEMPT_NO = previousAttemptCount; // Test Parameter
        final int MAX_ATTEMPTS = 2; //

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();
        String testRequestBody = realObjectMapper.writeValueAsString(passportFormData);

        DocumentDataVerificationResult testDocumentDataVerificationResult =
                DocumentDataVerificationServiceResultDataGenerator.generate(passportFormData);
        if (documentVerified) {
            testDocumentDataVerificationResult.setChecksSucceeded(List.of("verification_check"));
            testDocumentDataVerificationResult.setContraIndicators(new ArrayList<>());
        } else {
            testDocumentDataVerificationResult.setChecksFailed(List.of("verification_check"));
        }

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
        sessionItem.setClientId("testNoChangeId");
        when(mockSessionService.validateSessionId(SESSION_ID)).thenReturn(sessionItem);

        // If max attempts is reached the user is redirected with no further attempts allowed
        // new attempt are allowed below max
        if (sessionItem.getAttemptCount() < MAX_ATTEMPTS) {
            // parsePassportFormRequest
            when(mockRequestEvent.getBody()).thenReturn(testRequestBody);
            when(mockDocumentDataVerificationService.verifyData(
                            any(ThirdPartyAPIService.class),
                            any(PassportFormData.class),
                            any(SessionItem.class),
                            eq(requestHeaders),
                            eq(Strategy.NO_CHANGE)))
                    .thenReturn(testDocumentDataVerificationResult);

            when(mockParameterStoreService.getCommonParameterValue(
                            DOCUMENT_CHECK_RESULT_TTL_PARAMETER))
                    .thenReturn("7200");
        }

        mockLambdaContext();

        APIGatewayProxyResponseEvent responseEvent =
                checkPassportHandler.handleRequest(mockRequestEvent, mockLambdaContext);

        JsonNode responseTreeRootNode = realObjectMapper.readTree(responseEvent.getBody());

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe)
                .counterMetric(eq(LAMBDA_CHECK_PASSPORT_FUNCTION_INIT_DURATION), anyDouble());

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

            DocumentCheckResultItem documentCheckResultItem =
                    mapDocumentDataVerificationResultToDocumentCheckResultItem(
                            sessionItem, testDocumentDataVerificationResult, passportFormData);
            verify(mockDocumentCheckResultStore).create(documentCheckResultItem);
            verify(mockDocumentDataVerificationService)
                    .verifyData(
                            any(ThirdPartyAPIService.class),
                            eq(passportFormData),
                            any(SessionItem.class),
                            eq(requestHeaders),
                            eq(Strategy.NO_CHANGE));

        } else if (sessionItem.getAttemptCount() < MAX_ATTEMPTS && !documentVerified) {
            // Any attempt below max attempts where the document is NOT verified
            inOrder.verify(mockEventProbe).counterMetric(FORM_DATA_PARSE_PASS);

            inOrder.verify(mockEventProbe)
                    .counterMetric(LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_RETRY);
            verify(mockDocumentDataVerificationService)
                    .verifyData(
                            any(ThirdPartyAPIService.class),
                            eq(passportFormData),
                            any(SessionItem.class),
                            eq(requestHeaders),
                            eq(Strategy.NO_CHANGE));

            assertEquals(RESULT_RETRY, responseTreeRootNode.get(RESULT).textValue());
        } else if (sessionItem.getAttemptCount() == MAX_ATTEMPTS && !documentVerified) {
            // The last possible attempt reaches max attempts and the document is NOT verified
            inOrder.verify(mockEventProbe).counterMetric(FORM_DATA_PARSE_PASS);

            inOrder.verify(mockEventProbe)
                    .counterMetric(LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_UNVERIFIED);

            assertEquals(SESSION_ID, responseTreeRootNode.get("session_id").textValue());
            assertEquals(STATE, responseTreeRootNode.get("state").textValue());
            assertEquals(REDIRECT_URI, responseTreeRootNode.get("redirect_uri").textValue());

            DocumentCheckResultItem documentCheckResultItem =
                    mapDocumentDataVerificationResultToDocumentCheckResultItem(
                            sessionItem, testDocumentDataVerificationResult, passportFormData);
            verify(mockDocumentCheckResultStore).create(documentCheckResultItem);
            verify(mockDocumentDataVerificationService)
                    .verifyData(
                            any(ThirdPartyAPIService.class),
                            eq(passportFormData),
                            any(SessionItem.class),
                            eq(requestHeaders),
                            eq(Strategy.NO_CHANGE));

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
        sessionItem.setClientId("testNoChangeId");

        if (exceptionType.equals("SessionNotFoundException")) {
            when(mockSessionService.validateSessionId(SESSION_ID))
                    .thenThrow(new SessionNotFoundException("session not found"));
        } else {
            when(mockSessionService.validateSessionId(SESSION_ID))
                    .thenThrow(new SessionExpiredException("session expired"));
        }

        mockLambdaContext();

        APIGatewayProxyResponseEvent responseEvent =
                checkPassportHandler.handleRequest(mockRequestEvent, mockLambdaContext);

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe)
                .counterMetric(eq(LAMBDA_CHECK_PASSPORT_FUNCTION_INIT_DURATION), anyDouble());
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
        sessionItem.setClientId("testNoChangeId");
        when(mockSessionService.validateSessionId(SESSION_ID)).thenReturn(sessionItem);

        // parsePassportFormRequest
        when(mockRequestEvent.getBody()).thenReturn(testRequestBody);

        mockLambdaContext();

        APIGatewayProxyResponseEvent responseEvent =
                checkPassportHandler.handleRequest(mockRequestEvent, mockLambdaContext);

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe)
                .counterMetric(eq(LAMBDA_CHECK_PASSPORT_FUNCTION_INIT_DURATION), anyDouble());
        inOrder.verify(mockEventProbe).counterMetric(FORM_DATA_PARSE_FAIL);
        inOrder.verify(mockEventProbe).counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);
        verifyNoMoreInteractions(mockEventProbe);

        JsonNode responseTreeRootNode = realObjectMapper.readTree(responseEvent.getBody());
        JsonNode oauthErrorNode = responseTreeRootNode.get("oauth_error");

        CommonExpressOAuthError expectedObject =
                new CommonExpressOAuthError(
                        OAuth2Error.SERVER_ERROR, OAuth2Error.SERVER_ERROR.getDescription());

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
            throws JsonProcessingException, OAuthErrorResponseException {
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
        sessionItem.setClientId("NoChangeClientID");
        when(mockSessionService.validateSessionId(SESSION_ID)).thenReturn(sessionItem);

        when(mockDocumentDataVerificationService.verifyData(
                        any(ThirdPartyAPIService.class),
                        any(PassportFormData.class),
                        eq(sessionItem),
                        eq(requestHeaders),
                        eq(Strategy.NO_CHANGE)))
                .thenThrow(new RuntimeException("An Unhandled exception that has occurred"));

        mockLambdaContext();

        APIGatewayProxyResponseEvent responseEvent =
                checkPassportHandler.handleRequest(mockRequestEvent, mockLambdaContext);

        verify(mockDocumentDataVerificationService)
                .verifyData(
                        any(ThirdPartyAPIService.class),
                        eq(passportFormData),
                        any(SessionItem.class),
                        eq(requestHeaders),
                        eq(Strategy.NO_CHANGE));

        JsonNode responseTreeRootNode = realObjectMapper.readTree(responseEvent.getBody());
        JsonNode oauthErrorNode = responseTreeRootNode.get("oauth_error");

        CommonExpressOAuthError expectedObject =
                new CommonExpressOAuthError(
                        OAuth2Error.SERVER_ERROR, OAuth2Error.SERVER_ERROR.getDescription());

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

    @Test
    void handleResponseShouldThrowExceptionWhenSessionIdMissing() throws JsonProcessingException {
        APIGatewayProxyRequestEvent mockRequestEvent =
                Mockito.mock(APIGatewayProxyRequestEvent.class);

        Map<String, String> headers = new HashMap<>();

        when(mockRequestEvent.getHeaders()).thenReturn(headers);

        APIGatewayProxyResponseEvent responseEvent =
                checkPassportHandler.handleRequest(mockRequestEvent, mockLambdaContext);

        JsonNode responseTreeRootNode = new ObjectMapper().readTree(responseEvent.getBody());
        JsonNode oauthErrorNode = responseTreeRootNode.get("oauth_error");

        CommonExpressOAuthError expectedObject =
                new CommonExpressOAuthError(
                        OAuth2Error.ACCESS_DENIED, SESSION_NOT_FOUND.getMessage());

        assertNotNull(responseEvent);
        assertNotNull(responseTreeRootNode);
        assertNotNull(oauthErrorNode);
        assertEquals(HttpStatusCode.FORBIDDEN, responseEvent.getStatusCode());

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

    private void mockServiceFactoryBehaviour() {
        when(mockServiceFactory.getObjectMapper()).thenReturn(realObjectMapper);
        when(mockServiceFactory.getEventProbe()).thenReturn(mockEventProbe);

        when(mockServiceFactory.getApacheHTTPClientFactoryService())
                .thenReturn(mockApacheHTTPClientFactoryService);

        when(mockServiceFactory.getParameterStoreService()).thenReturn(mockParameterStoreService);

        when(mockServiceFactory.getSessionService()).thenReturn(mockSessionService);

        when(mockServiceFactory.getPersonIdentityService()).thenReturn(mockPersonIdentityService);

        when(mockServiceFactory.getDocumentCheckResultStore())
                .thenReturn(mockDocumentCheckResultStore);
    }

    private DocumentCheckResultItem mapDocumentDataVerificationResultToDocumentCheckResultItem(
            SessionItem sessionItem,
            DocumentDataVerificationResult documentDataVerificationResult,
            PassportFormData passportFormData) {
        DocumentCheckResultItem documentCheckResultItem = new DocumentCheckResultItem();

        documentCheckResultItem.setSessionId(sessionItem.getSessionId());

        documentCheckResultItem.setTransactionId(documentDataVerificationResult.getTransactionId());
        documentCheckResultItem.setContraIndicators(
                documentDataVerificationResult.getContraIndicators());
        documentCheckResultItem.setStrengthScore(documentDataVerificationResult.getStrengthScore());
        documentCheckResultItem.setValidityScore(documentDataVerificationResult.getValidityScore());

        String passportNo = passportFormData.getPassportNumber();
        String passportExpiryDate = String.valueOf(passportFormData.getExpiryDate());
        documentCheckResultItem.setDocumentNumber(passportNo);
        documentCheckResultItem.setExpiryDate(passportExpiryDate);

        documentCheckResultItem.setCheckDetails(
                documentDataVerificationResult.getChecksSucceeded());
        documentCheckResultItem.setFailedCheckDetails(
                documentDataVerificationResult.getChecksFailed());
        documentCheckResultItem.setCiReasons(new ArrayList<>());
        return documentCheckResultItem;
    }

    private void mockLambdaContext() {
        when(mockLambdaContext.getFunctionName()).thenReturn("functionName");
        when(mockLambdaContext.getFunctionVersion()).thenReturn("1.0");
    }
}
