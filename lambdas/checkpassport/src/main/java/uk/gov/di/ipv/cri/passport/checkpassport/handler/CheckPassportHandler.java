package uk.gov.di.ipv.cri.passport.checkpassport.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.CorrelationIdPathConstants;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.BirthDate;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.SharedClaims;
import uk.gov.di.ipv.cri.common.library.exception.SessionExpiredException;
import uk.gov.di.ipv.cri.common.library.exception.SessionNotFoundException;
import uk.gov.di.ipv.cri.common.library.persistence.DataStore;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.PersonIdentityService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.DocumentDataVerificationResult;
import uk.gov.di.ipv.cri.passport.checkpassport.services.ContraIndicatorMapper;
import uk.gov.di.ipv.cri.passport.checkpassport.services.DocumentDataVerificationService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.FormDataValidator;
import uk.gov.di.ipv.cri.passport.checkpassport.services.ThirdPartyAPIServiceFactory;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.domain.Strategy;
import uk.gov.di.ipv.cri.passport.library.error.CommonExpressOAuthError;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;
import uk.gov.di.ipv.cri.passport.library.helpers.PersonIdentityDetailedHelperMapper;
import uk.gov.di.ipv.cri.passport.library.logging.LoggingSupport;
import uk.gov.di.ipv.cri.passport.library.metrics.Definitions;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;
import uk.gov.di.ipv.cri.passport.library.service.ThirdPartyAPIService;

import java.time.Clock;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static uk.gov.di.ipv.cri.common.library.error.ErrorResponse.SESSION_EXPIRED;
import static uk.gov.di.ipv.cri.common.library.error.ErrorResponse.SESSION_NOT_FOUND;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DOCUMENT_CHECK_RESULT_TTL_PARAMETER;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.*;

public class CheckPassportHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    // We need this first and static for it to be created as soon as possible during function init
    private static final long FUNCTION_INIT_START_TIME_MILLISECONDS = System.currentTimeMillis();

    private static final Logger LOGGER = LogManager.getLogger();

    private static final boolean DEV_ENVIRONMENT_ONLY_ENHANCED_DEBUG =
            Boolean.parseBoolean(System.getenv("DEV_ENVIRONMENT_ONLY_ENHANCED_DEBUG"));

    // Maximum submissions from the front end form
    private static final int MAX_ATTEMPTS = 2;

    // Return values for retry scenario
    public static final String RESULT = "result";
    public static final String RESULT_RETRY = "retry";

    private ParameterStoreService parameterStoreService;

    // CRI-Lib Common Services and objects
    private EventProbe eventProbe;
    private SessionService sessionService;
    private PersonIdentityService personIdentityService;

    // Passport Common Services and objects
    private ObjectMapper objectMapper;

    // Check Passport only service
    private DocumentDataVerificationService documentDataVerificationService;

    // Shared DataStore (Write)
    private DataStore<DocumentCheckResultItem> documentCheckResultStore;

    private ThirdPartyAPIServiceFactory thirdPartyAPIServiceFactory;

    private long functionInitMetricLatchedValue = 0;
    private boolean functionInitMetricCaptured = false;

    @ExcludeFromGeneratedCoverageReport
    public CheckPassportHandler() throws JsonProcessingException {
        // A reference to serviceFactory is not held in this class
        ServiceFactory serviceFactory = new ServiceFactory();

        // DocumentDataVerificationService is internal to CheckPassportHandler
        DocumentDataVerificationService documentDataVerificationServiceNotAssignedYet =
                new DocumentDataVerificationService(
                        serviceFactory,
                        new FormDataValidator(),
                        new ContraIndicatorMapper(serviceFactory));

        // initializeLambdaServices is used to reduce uncovered code in the default constructor
        initializeLambdaServices(serviceFactory, documentDataVerificationServiceNotAssignedYet);
    }

    public CheckPassportHandler(
            ServiceFactory serviceFactory,
            DocumentDataVerificationService documentDataVerificationService)
            throws JsonProcessingException {
        initializeLambdaServices(serviceFactory, documentDataVerificationService);
    }

    private void initializeLambdaServices(
            ServiceFactory serviceFactory,
            DocumentDataVerificationService documentDataVerificationService)
            throws JsonProcessingException {
        this.objectMapper = serviceFactory.getObjectMapper();
        this.parameterStoreService = serviceFactory.getParameterStoreService();

        this.eventProbe = serviceFactory.getEventProbe();
        this.sessionService = serviceFactory.getSessionService();
        this.personIdentityService = serviceFactory.getPersonIdentityService();

        this.documentDataVerificationService = documentDataVerificationService;

        this.documentCheckResultStore = serviceFactory.getDocumentCheckResultStore();

        this.thirdPartyAPIServiceFactory = new ThirdPartyAPIServiceFactory(serviceFactory);

        // Runtime/SnapStart function init duration
        functionInitMetricLatchedValue =
                System.currentTimeMillis() - FUNCTION_INIT_START_TIME_MILLISECONDS;
    }

    @Override
    @Logging(clearState = true, correlationIdPath = CorrelationIdPathConstants.API_GATEWAY_REST)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            // There is logging before the session read which attaches journey keys
            // We clear these persistent ones now so these not attributed to any previous journey
            LoggingSupport.clearPersistentJourneyKeys();

            LOGGER.info(
                    "Initiating lambda {} version {}",
                    context.getFunctionName(),
                    context.getFunctionVersion());

            // Recorded here as sending metrics during function init may fail depending on lambda
            // config
            if (!functionInitMetricCaptured) {
                eventProbe.counterMetric(
                        Definitions.LAMBDA_CHECK_PASSPORT_FUNCTION_INIT_DURATION,
                        functionInitMetricLatchedValue);
                LOGGER.info("Lambda function init duration {}ms", functionInitMetricLatchedValue);
                functionInitMetricCaptured = true;
            }

            long runTimeDuration =
                    System.currentTimeMillis() - FUNCTION_INIT_START_TIME_MILLISECONDS;

            Duration duration = Duration.of(runTimeDuration, ChronoUnit.MILLIS);

            String formattedDuration =
                    String.format(
                            "%d:%02d:%02d",
                            duration.toHours(), duration.toMinutesPart(), duration.toSecondsPart());

            LOGGER.info(
                    "Lambda {}, Lifetime duration {}, {}ms",
                    context.getFunctionName(),
                    formattedDuration,
                    runTimeDuration);

            Map<String, String> requestHeaders = input.getHeaders();
            String sessionId = retrieveSessionIdFromHeaders(requestHeaders);

            LOGGER.info("Extracting session from header ID {}", sessionId);
            SessionItem sessionItem = sessionService.validateSessionId(sessionId);
            LOGGER.info("Persistent Logging keys now attached to sessionId {}", sessionId);

            String clientId = sessionItem.getClientId();
            Strategy thirdPartyRouting = Strategy.fromClientIdString(clientId);

            LOGGER.info("IPV Core Client Id {}, Routing set to {}", clientId, thirdPartyRouting);

            // Attempt start
            sessionItem.setAttemptCount(sessionItem.getAttemptCount() + 1);
            LOGGER.info("Attempt Number {}", sessionItem.getAttemptCount());

            // Check we are not "now" above max_attempts to prevent doing another remote API call
            if (sessionItem.getAttemptCount() > MAX_ATTEMPTS) {

                // We do not treat this as a journey fail condition
                // The user has had multiple attempts recorded, we attempt to redirect them on
                LOGGER.warn(
                        "Attempt count {} is over the max of {}",
                        sessionItem.getAttemptCount(),
                        MAX_ATTEMPTS);

                eventProbe.counterMetric(LAMBDA_CHECK_PASSPORT_USER_REDIRECTED_ATTEMPTS_OVER_MAX);

                APIGatewayProxyResponseEvent responseEvent =
                        passportSuccessResponseEvent(sessionItem);

                // Use the completed OK exit sequence
                return lambdaCompletedOK(responseEvent);
            }
            ThirdPartyAPIService thirdPartyAPIService;
            PassportFormData passportFormData = parsePassportFormRequest(input.getBody());
            eventProbe.counterMetric(FORM_DATA_PARSE_PASS);
            // ClientID dictates switch conditional, return new api service based on clientID value
            if (thirdPartyRouting == Strategy.STUB) {
                thirdPartyAPIService =
                        thirdPartyAPIServiceFactory.getDvadThirdPartyAPIServiceForStub();
            } else {
                thirdPartyAPIService = thirdPartyAPIServiceFactory.getDvadThirdPartyAPIService();
            }

            LOGGER.info("Thirdparty API service is {}", thirdPartyAPIService.getServiceName());

            DocumentDataVerificationResult documentDataVerificationResult =
                    documentDataVerificationService.verifyData(
                            thirdPartyAPIService,
                            passportFormData,
                            sessionItem,
                            requestHeaders,
                            thirdPartyRouting);

            saveAttempt(sessionItem, passportFormData, documentDataVerificationResult);

            boolean canRetry =
                    determineVerificationRetryStatus(
                            sessionItem, documentDataVerificationResult, MAX_ATTEMPTS);
            LOGGER.info("CanRetry {}", canRetry);

            APIGatewayProxyResponseEvent responseEvent =
                    determineExitResponseEvent(sessionItem, canRetry);

            // Use the completed OK exit sequence
            return lambdaCompletedOK(responseEvent);
        } catch (SessionNotFoundException e) {
            LOGGER.error(e.getMessage(), e);
            eventProbe.counterMetric(Definitions.LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.FORBIDDEN,
                    new CommonExpressOAuthError(
                            OAuth2Error.ACCESS_DENIED, SESSION_NOT_FOUND.getMessage()));
        } catch (SessionExpiredException e) {
            LOGGER.error(e.getMessage(), e);
            eventProbe.counterMetric(Definitions.LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.FORBIDDEN,
                    new CommonExpressOAuthError(
                            OAuth2Error.ACCESS_DENIED, SESSION_EXPIRED.getMessage()));
        } catch (NumberFormatException e) {
            LOGGER.error(
                    "Error calling parse on {} to convert to an int,long or double - Exception {}",
                    e.getMessage(),
                    e.getClass());
            eventProbe.counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    new CommonExpressOAuthError(OAuth2Error.SERVER_ERROR));
        } catch (IllegalArgumentException e) {
            // Order important as NumberFormatException is also an IllegalArgumentException
            LOGGER.error(e.getMessage(), e);
            eventProbe.counterMetric(Definitions.LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);
            // Oauth compliant response
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    new CommonExpressOAuthError(OAuth2Error.SERVER_ERROR));
        } catch (OAuthErrorResponseException e) {
            eventProbe.counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);

            // Debug in DEV only as Oauth errors appear in the redirect url
            // This will output the specific error message
            // Note Unit tests expect server error (correctly)
            // and will fail if this is set (during unit tests)
            if (DEV_ENVIRONMENT_ONLY_ENHANCED_DEBUG) {
                String customOAuth2ErrorDescription = e.getErrorReason();
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        e.getStatusCode(), // Status Code determined by throw location
                        new CommonExpressOAuthError(
                                OAuth2Error.SERVER_ERROR, customOAuth2ErrorDescription));
            }

            // Non-debug route - standard OAuth2Error.SERVER_ERROR
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getStatusCode(), // Status Code determined by throw location
                    new CommonExpressOAuthError(OAuth2Error.SERVER_ERROR));
        } catch (Exception e) {
            // This is where unexpected exceptions will reach (null pointers etc)
            // Expected exceptions should be caught and thrown as
            // OAuthErrorResponseException
            // We should not log unknown exceptions, due to possibility of PII
            LOGGER.error(
                    "Unhandled Exception while handling lambda {} exception {}",
                    context.getFunctionName(),
                    e.getClass());

            LOGGER.debug(e.getMessage(), e);

            eventProbe.counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    new CommonExpressOAuthError(OAuth2Error.SERVER_ERROR));
        }
    }

    public boolean sessionIdIsNotUUID(String sessionId) {
        Pattern uuidRegex =
                Pattern.compile(
                        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
        return !uuidRegex.matcher(sessionId).matches();
    }

    private boolean determineVerificationRetryStatus(
            SessionItem sessionItem,
            DocumentDataVerificationResult documentDataVerificationResult,
            final int MAX_ATTEMPTS) {

        if (documentDataVerificationResult.isVerified()
                && (documentDataVerificationResult.getContraIndicators() == null
                        || documentDataVerificationResult.getContraIndicators().isEmpty())) {
            LOGGER.info("Document verified");
            eventProbe.counterMetric(
                    LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_VERIFIED_PREFIX
                            + sessionItem.getAttemptCount());

            return false;
        } else if (sessionItem.getAttemptCount() >= MAX_ATTEMPTS) {
            LOGGER.info(
                    "Ending document verification after {} attempts",
                    sessionItem.getAttemptCount());
            eventProbe.counterMetric(LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_UNVERIFIED);

            return false;
        } else {
            LOGGER.info("Document not verified at attempt {}", sessionItem.getAttemptCount());
            eventProbe.counterMetric(LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_RETRY);

            return true;
        }
    }

    private APIGatewayProxyResponseEvent determineExitResponseEvent(
            SessionItem sessionItem, boolean canRetry) {
        if (canRetry) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.OK, Map.of(RESULT, RESULT_RETRY));
        } else {
            return passportSuccessResponseEvent(sessionItem);
        }
    }

    private APIGatewayProxyResponseEvent passportSuccessResponseEvent(SessionItem sessionItem) {

        String sessionId = sessionItem.getSessionId().toString();
        String state = sessionItem.getState();
        String redirectURI = sessionItem.getRedirectUri().toString();

        return ApiGatewayResponseGenerator.proxyJsonResponse(
                HttpStatusCode.OK, new CheckPassportSuccessResponse(sessionId, state, redirectURI));
    }

    // Method used to prevent completed ok paths diverging
    private APIGatewayProxyResponseEvent lambdaCompletedOK(
            APIGatewayProxyResponseEvent responseEvent) {

        // Lambda Complete No Error
        eventProbe.counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_OK);

        return responseEvent;
    }

    private PassportFormData parsePassportFormRequest(String input)
            throws OAuthErrorResponseException {
        LOGGER.info("Parsing passport form data into payload for third party document check");
        try {
            return objectMapper.readValue(input, PassportFormData.class);
        } catch (JsonProcessingException e) {
            // NOTE e.getMessage() contains form PII,  e.getOriginalMessage() is just the field name
            LOGGER.error(
                    String.format(
                            "Failed to parse payload from input: %S", e.getOriginalMessage()));
            eventProbe.counterMetric(FORM_DATA_PARSE_FAIL);
            throw new OAuthErrorResponseException(
                    HttpStatusCode.BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA);
        }
    }

    private void saveAttempt(
            SessionItem sessionItem,
            PassportFormData passportFormData,
            DocumentDataVerificationResult documentDataVerificationResult) {

        // TODO - DocumentDataVerificationResult - record only the form fields which are used in
        // each specific API Request

        LOGGER.info("Saving person identity...");
        BirthDate birthDate = new BirthDate();
        birthDate.setValue(passportFormData.getDateOfBirth());

        SharedClaims sharedClaims = new SharedClaims();
        sharedClaims.setBirthDates(List.of(birthDate));
        sharedClaims.setNames(
                List.of(
                        PersonIdentityDetailedHelperMapper.mapNamesToCanonicalName(
                                passportFormData.getForenames(), passportFormData.getSurname())));

        LOGGER.info("Saving Person identity");
        personIdentityService.savePersonIdentity(sessionItem.getSessionId(), sharedClaims);
        LOGGER.info("Person identity saved.");

        LOGGER.info("Saving document check results...");
        final DocumentCheckResultItem documentCheckResultItem =
                mapDocumentDataVerificationResultToDocumentCheckResultItem(
                        sessionItem, documentDataVerificationResult, passportFormData);

        documentCheckResultStore.create(documentCheckResultItem);
        LOGGER.info("Document check results saved.");

        // NOTE: sessionItem.attemptCount is persisted at this point as
        // a side effect of createAuthorizationCode internally
        // calling updateSession() to persist the authorization code
        // There is no need to-do two separate db calls
        LOGGER.info("Generating authorization code...");
        sessionService.createAuthorizationCode(sessionItem);
        LOGGER.info("Authorization code generated...");
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
        documentCheckResultItem.setCiReasons(
                documentDataVerificationResult.getContraIndicatorReasons());

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

        final long ttl =
                Long.parseLong(
                        parameterStoreService.getCommonParameterValue(
                                DOCUMENT_CHECK_RESULT_TTL_PARAMETER));

        documentCheckResultItem.setTtl(
                Clock.systemUTC().instant().plus(ttl, ChronoUnit.SECONDS).getEpochSecond());

        return documentCheckResultItem;
    }

    private String retrieveSessionIdFromHeaders(Map<String, String> headers) {

        if (headers == null) {
            throw new SessionNotFoundException("Request had no headers");
        }

        String sessionId = headers.get("session_id");

        if (sessionId == null) {
            throw new SessionNotFoundException("Header session_id not found");
        }

        if (sessionIdIsNotUUID(sessionId)) {
            throw new SessionNotFoundException("Header session_id value not a UUID");
        }

        return sessionId;
    }
}
