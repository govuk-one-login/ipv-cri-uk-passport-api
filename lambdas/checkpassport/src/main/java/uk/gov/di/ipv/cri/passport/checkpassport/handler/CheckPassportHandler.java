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
import uk.gov.di.ipv.cri.passport.checkpassport.services.ThirdPartyAPIService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.ThirdPartyAPIServiceFactory;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.error.CommonExpressOAuthError;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;
import uk.gov.di.ipv.cri.passport.library.helpers.PersonIdentityDetailedHelperMapper;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.cri.common.library.error.ErrorResponse.SESSION_EXPIRED;
import static uk.gov.di.ipv.cri.common.library.error.ErrorResponse.SESSION_NOT_FOUND;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DOCUMENT_CHECK_RESULT_TTL_PARAMETER;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DVA_DIGITAL_ENABLED;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.MAXIMUM_ATTEMPT_COUNT;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.FORM_DATA_PARSE_FAIL;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.FORM_DATA_PARSE_PASS;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_RETRY;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_UNVERIFIED;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_VERIFIED_PREFIX;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_COMPLETED_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CHECK_PASSPORT_USER_REDIRECTED_ATTEMPTS_OVER_MAX;

public class CheckPassportHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LogManager.getLogger();

    // Header Keys
    public static final String HEADER_DOCUMENT_CHECKING_ROUTE = "document-checking-route";

    // Return values for retry scenario
    public static final String RESULT = "result";
    public static final String RESULT_RETRY = "retry";

    private PassportConfigurationService passportConfigurationService;

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

    public CheckPassportHandler() {
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
            DocumentDataVerificationService documentDataVerificationService) {
        initializeLambdaServices(serviceFactory, documentDataVerificationService);
    }

    private void initializeLambdaServices(
            ServiceFactory serviceFactory,
            DocumentDataVerificationService documentDataVerificationService) {
        this.objectMapper = serviceFactory.getObjectMapper();
        this.passportConfigurationService = serviceFactory.getPassportConfigurationService();

        this.eventProbe = serviceFactory.getEventProbe();
        this.sessionService = serviceFactory.getSessionService();
        this.personIdentityService = serviceFactory.getPersonIdentityService();

        this.documentDataVerificationService = documentDataVerificationService;

        this.documentCheckResultStore = serviceFactory.getDocumentCheckResultStore();

        this.thirdPartyAPIServiceFactory = new ThirdPartyAPIServiceFactory(serviceFactory);
    }

    @Override
    @Logging(clearState = true, correlationIdPath = CorrelationIdPathConstants.API_GATEWAY_REST)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            LOGGER.info(
                    "Initiating lambda {} version {}",
                    context.getFunctionName(),
                    context.getFunctionVersion());

            Map<String, String> requestHeaders = input.getHeaders();
            String sessionId = requestHeaders.get("session_id");
            LOGGER.info("Extracting session from header ID {}", sessionId);
            var sessionItem = sessionService.validateSessionId(sessionId);

            // Attempt Start
            final int MAX_ATTEMPTS =
                    Integer.parseInt(
                            passportConfigurationService.getStackParameterValue(
                                    MAXIMUM_ATTEMPT_COUNT));

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

            PassportFormData passportFormData = parsePassportFormRequest(input.getBody());
            eventProbe.counterMetric(FORM_DATA_PARSE_PASS);

            // Dynamic Third party API selection based on new-api header key being present (value
            // ignored)
            boolean dvaDigitalEnabled =
                    Boolean.parseBoolean(
                            passportConfigurationService.getStackParameterValue(
                                    DVA_DIGITAL_ENABLED));
            boolean newThirdpartyAPI =
                    "dvad".equals(requestHeaders.get(HEADER_DOCUMENT_CHECKING_ROUTE));

            ThirdPartyAPIService thirdPartyAPIService =
                    selectThirdPartyAPIService(dvaDigitalEnabled, newThirdpartyAPI);

            DocumentDataVerificationResult documentDataVerificationResult =
                    documentDataVerificationService.verifyData(
                            thirdPartyAPIService, passportFormData, sessionItem, requestHeaders);

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

            String customOAuth2ErrorDescription = SESSION_NOT_FOUND.getMessage();
            LOGGER.error(customOAuth2ErrorDescription);
            eventProbe.counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);

            LOGGER.debug(e.getMessage(), e);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.FORBIDDEN,
                    new CommonExpressOAuthError(
                            OAuth2Error.ACCESS_DENIED, customOAuth2ErrorDescription));
        } catch (SessionExpiredException e) {

            String customOAuth2ErrorDescription = SESSION_EXPIRED.getMessage();
            LOGGER.error(customOAuth2ErrorDescription);
            eventProbe.counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);

            LOGGER.debug(e.getMessage(), e);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.FORBIDDEN,
                    new CommonExpressOAuthError(
                            OAuth2Error.ACCESS_DENIED, customOAuth2ErrorDescription));
        } catch (NumberFormatException e) {
            LOGGER.error(
                    "Error calling parse on {} to convert to an int,long or double - Exception {}",
                    e.getMessage(),
                    e.getClass());
            eventProbe.counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    new CommonExpressOAuthError(OAuth2Error.SERVER_ERROR));
        } catch (OAuthErrorResponseException e) {
            eventProbe.counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);

            // Debug only as Oauth errors appear in the redirect url
            // This will output the specific error message
            // Note Unit tests expect server error (correctly)
            // and will fail if logging is at debug level (during tests)
            if (LOGGER.isDebugEnabled()) {
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

            if (LOGGER.isDebugEnabled()) {
                e.printStackTrace();
            }

            eventProbe.counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    new CommonExpressOAuthError(OAuth2Error.SERVER_ERROR));
        }
    }

    private boolean determineVerificationRetryStatus(
            SessionItem sessionItem,
            DocumentDataVerificationResult documentDataVerificationResult,
            final int MAX_ATTEMPTS) {

        if (documentDataVerificationResult.isVerified()) {
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
        LOGGER.info("Authorization code saved.");
    }

    private ThirdPartyAPIService selectThirdPartyAPIService(
            boolean dvaDigitalEnabled, boolean newThirdpartyAPI) {
        // Feature flag and header required for new api
        if (dvaDigitalEnabled && newThirdpartyAPI) {
            // DVAD
            return thirdPartyAPIServiceFactory.getDvadThirdPartyAPIService();
        } else {
            // Legacy DCS
            return thirdPartyAPIServiceFactory.getDcsThirdPartyAPIService();
        }
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

        final long ttl =
                Long.parseLong(
                        passportConfigurationService.getCommonParameterValue(
                                DOCUMENT_CHECK_RESULT_TTL_PARAMETER));

        documentCheckResultItem.setTtl(
                Clock.systemUTC().instant().plus(ttl, ChronoUnit.SECONDS).getEpochSecond());

        return documentCheckResultItem;
    }
}
