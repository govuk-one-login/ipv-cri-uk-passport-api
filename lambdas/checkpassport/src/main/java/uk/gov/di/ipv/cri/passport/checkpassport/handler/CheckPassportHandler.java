package uk.gov.di.ipv.cri.passport.checkpassport.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.client.HttpClient;
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
import uk.gov.di.ipv.cri.common.library.service.AuditService;
import uk.gov.di.ipv.cri.common.library.service.PersonIdentityService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.CheckPassportSuccessResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.DocumentDataVerificationResult;
import uk.gov.di.ipv.cri.passport.checkpassport.exception.OAuthHttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.cri.passport.checkpassport.services.DcsCryptographyService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.DocumentDataVerificationService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.FormDataValidator;
import uk.gov.di.ipv.cri.passport.checkpassport.services.ThirdPartyAPIService;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.error.CommonExpressOAuthError;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.helpers.PersonIdentityDetailedHelperMapper;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;

import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.cri.common.library.error.ErrorResponse.SESSION_EXPIRED;
import static uk.gov.di.ipv.cri.common.library.error.ErrorResponse.SESSION_NOT_FOUND;
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

    public static final String RESULT = "result";
    public static final String RESULT_RETRY = "retry";

    private final PassportConfigurationService passportConfigurationService;

    // CRI-Lib Common Services and objects
    private final EventProbe eventProbe;
    private final SessionService sessionService;
    private final PersonIdentityService personIdentityService;

    // Passport Common Services and objects
    private final ObjectMapper objectMapper;

    // Check Passport only service
    private final DocumentDataVerificationService documentDataVerificationService;

    // Shared DataStore (Write)
    private final DataStore<DocumentCheckResultItem> documentCheckResultStore;

    public CheckPassportHandler() {
        ServiceFactory serviceFactory = new ServiceFactory();

        this.objectMapper = serviceFactory.getObjectMapper();
        this.passportConfigurationService = serviceFactory.getPassportConfigurationService();

        this.eventProbe = serviceFactory.getEventProbe();
        this.sessionService = serviceFactory.getSessionService();
        this.personIdentityService = serviceFactory.getPersonIdentityService();

        // Service is internal to CheckPassportHandler
        this.documentDataVerificationService =
                constructDocumentDataVerificationService(serviceFactory);

        this.documentCheckResultStore = serviceFactory.getDocumentCheckResultStore();
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckPassportHandler(
            ServiceFactory serviceFactory,
            DocumentDataVerificationService documentDataVerificationService) {
        this.objectMapper = serviceFactory.getObjectMapper();
        this.passportConfigurationService = serviceFactory.getPassportConfigurationService();

        this.eventProbe = serviceFactory.getEventProbe();
        this.sessionService = serviceFactory.getSessionService();
        this.personIdentityService = serviceFactory.getPersonIdentityService();

        this.documentDataVerificationService = documentDataVerificationService;

        this.documentCheckResultStore = serviceFactory.getDocumentCheckResultStore();
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
                            passportConfigurationService.getParameterValue(MAXIMUM_ATTEMPT_COUNT));

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

            DocumentDataVerificationResult documentDataVerificationResult =
                    documentDataVerificationService.verifyData(
                            passportFormData, sessionItem, requestHeaders);

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
        } catch (OAuthHttpResponseExceptionWithErrorBody e) {
            eventProbe.counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);

            LOGGER.debug(e.getMessage(), e);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getStatusCode(), // Status Code determined by throw location
                    new CommonExpressOAuthError(OAuth2Error.SERVER_ERROR));
        } catch (Exception e) {
            eventProbe.counterMetric(LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR);
            // Cannot log e, due to possibility of PII
            LOGGER.error("Check Passport Unhandled Exception");

            LOGGER.debug(e.getMessage(), e);

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
            throws OAuthHttpResponseExceptionWithErrorBody {
        LOGGER.info("Parsing passport form data into payload for third party document check");
        try {
            return objectMapper.readValue(input, PassportFormData.class);
        } catch (JsonProcessingException e) {
            // NOTE e.getMessage() contains form PII,  e.getOriginalMessage() is just the field name
            LOGGER.error(
                    String.format(
                            "Failed to parse payload from input: %S", e.getOriginalMessage()));
            eventProbe.counterMetric(FORM_DATA_PARSE_FAIL);
            throw new OAuthHttpResponseExceptionWithErrorBody(
                    HttpStatusCode.BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA);
        }
    }

    private void saveAttempt(
            SessionItem sessionItem,
            PassportFormData passportFormData,
            DocumentDataVerificationResult documentDataVerificationResult) {

        // NOTE: sessionItem.attemptCount is persisted at this point as
        // a side effect of createAuthorizationCode internally
        // calling updateSession() to persist the authorization code
        // There is no need to-do two separate db calls
        LOGGER.info("Generating authorization code...");
        sessionService.createAuthorizationCode(sessionItem);

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

        final DocumentCheckResultItem documentCheckResultItem =
                mapDocumentDataVerificationResultToDocumentCheckResultItem(
                        sessionItem, documentDataVerificationResult, passportFormData);

        LOGGER.info("Saving document check results...");
        documentCheckResultStore.create(documentCheckResultItem);
        LOGGER.info("Document check results saved.");
    }

    private DocumentDataVerificationService constructDocumentDataVerificationService(
            ServiceFactory serviceFactory) {

        AuditService auditService = serviceFactory.getAuditService();

        String dvaDigitalEnabled =
                passportConfigurationService.getParameterValue(DVA_DIGITAL_ENABLED);
        ThirdPartyAPIService thirdPartyAPIService = null;
        if (dvaDigitalEnabled.equals("false")) {
            HttpClient httpClient =
                    serviceFactory
                            .getClientFactoryService()
                            .getLegacyHTTPClient(passportConfigurationService);

            thirdPartyAPIService =
                    new ThirdPartyAPIService(
                            passportConfigurationService,
                            eventProbe,
                            new DcsCryptographyService(passportConfigurationService),
                            httpClient);
        } else {
            HttpClient httpClient =
                    serviceFactory
                            .getClientFactoryService()
                            .getHTTPClient(passportConfigurationService);

            thirdPartyAPIService =
                    new ThirdPartyAPIService(
                            passportConfigurationService,
                            eventProbe,
                            new DcsCryptographyService(passportConfigurationService),
                            httpClient);
        }

        return new DocumentDataVerificationService(
                eventProbe, auditService, thirdPartyAPIService, new FormDataValidator());
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

        return documentCheckResultItem;
    }
}
