package uk.gov.di.ipv.cri.passport.issuecredential.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.CorrelationIdPaths;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.FlushMetrics;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventContext;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventType;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.PersonIdentityDetailed;
import uk.gov.di.ipv.cri.common.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.common.library.exception.AccessTokenExpiredException;
import uk.gov.di.ipv.cri.common.library.exception.SessionExpiredException;
import uk.gov.di.ipv.cri.common.library.exception.SessionNotFoundException;
import uk.gov.di.ipv.cri.common.library.exception.SqsException;
import uk.gov.di.ipv.cri.common.library.persistence.DataStore;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.PersonIdentityService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.common.library.util.KMSSigner;
import uk.gov.di.ipv.cri.passport.issuecredential.exception.CredentialRequestException;
import uk.gov.di.ipv.cri.passport.issuecredential.exception.DocumentCheckResultItemNotFoundException;
import uk.gov.di.ipv.cri.passport.issuecredential.exception.PersonIdentityDetailedNotFoundException;
import uk.gov.di.ipv.cri.passport.issuecredential.exception.SessionItemNotFoundException;
import uk.gov.di.ipv.cri.passport.issuecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.cri.passport.issuecredential.util.IssueCredentialPassportAuditExtensionUtil;
import uk.gov.di.ipv.cri.passport.library.error.CommonExpressOAuthError;
import uk.gov.di.ipv.cri.passport.library.helpers.PersonIdentityDetailedHelperMapper;
import uk.gov.di.ipv.cri.passport.library.logging.LoggingSupport;
import uk.gov.di.ipv.cri.passport.library.metrics.Definitions;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_ISSUE_CREDENTIAL_COMPLETED_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.PASSPORT_CI_PREFIX;

public class IssueCredentialHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    // We need this first and static for it to be created as soon as possible during function init
    private static final long FUNCTION_INIT_START_TIME_MILLISECONDS = System.currentTimeMillis();

    private static final Logger LOGGER = LoggerFactory.getLogger(IssueCredentialHandler.class);

    static {
        LoggingSupport.populateLambdaInitLoggerValues();
    }

    private static final String AUDIT_EVENT_LOG_FORMAT = "Sending AuditEvent {}";

    public static final String AUTHORIZATION_HEADER_KEY = "Authorization";
    private static final String LAMBDA_EXCEPTION_ERROR_MESSAGE =
            "Exception while handling lambda {} exception {}";
    private ConfigurationService commonLibConfigurationService;

    // CommonLib
    private EventProbe eventProbe;
    private SessionService sessionService;
    private PersonIdentityService personIdentityService;
    private AuditService auditService;

    // Issue Credential Specific
    private VerifiableCredentialService verifiableCredentialService;

    // Shared DataStore (Read)
    private DataStore<DocumentCheckResultItem> documentCheckResultStore;

    private long functionInitMetricLatchedValue = 0;
    private boolean functionInitMetricCaptured = false;

    @ExcludeFromGeneratedCoverageReport
    public IssueCredentialHandler() {
        // A reference to serviceFactory is not held in this class
        ServiceFactory serviceFactory = new ServiceFactory();

        KMSSigner kmsSigner =
                new KMSSigner(
                        serviceFactory
                                .getCommonLibConfigurationService()
                                .getVerifiableCredentialKmsSigningKeyId(),
                        serviceFactory.getClientProviderFactory().getKMSClient());

        // VerifiableCredentialService is internal to IssueCredentialHandler
        VerifiableCredentialService verifiableCredentialServiceNotAssignedYet =
                new VerifiableCredentialService(serviceFactory, kmsSigner);

        initializeLambdaServices(serviceFactory, verifiableCredentialServiceNotAssignedYet);
    }

    public IssueCredentialHandler(
            ServiceFactory serviceFactory,
            VerifiableCredentialService verifiableCredentialService) {
        initializeLambdaServices(serviceFactory, verifiableCredentialService);
    }

    private void initializeLambdaServices(
            ServiceFactory serviceFactory,
            VerifiableCredentialService verifiableCredentialService) {
        this.commonLibConfigurationService = serviceFactory.getCommonLibConfigurationService();

        this.eventProbe = serviceFactory.getEventProbe();
        this.sessionService = serviceFactory.getSessionService();
        this.auditService = serviceFactory.getAuditService();
        this.personIdentityService = serviceFactory.getPersonIdentityService();

        this.documentCheckResultStore = serviceFactory.getDocumentCheckResultStore();

        this.verifiableCredentialService = verifiableCredentialService;

        // Runtime/SnapStart function init duration
        functionInitMetricLatchedValue =
                System.currentTimeMillis() - FUNCTION_INIT_START_TIME_MILLISECONDS;
    }

    @Override
    @Logging(clearState = true, correlationIdPath = CorrelationIdPaths.API_GATEWAY_REST)
    @FlushMetrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        try {
            LOGGER.info(
                    "Initiating lambda {} version {}",
                    context.getFunctionName(),
                    context.getFunctionVersion());

            // Recorded here as sending metrics during function init may fail depending on lambda
            // config
            if (!functionInitMetricCaptured) {
                eventProbe.counterMetric(
                        Definitions.LAMBDA_ISSUE_CREDENTIAL_FUNCTION_INIT_DURATION,
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

            LOGGER.info("Validating access token...");
            AccessToken accessToken = validateInputHeaderBearerToken(input.getHeaders());

            LOGGER.info("Looking up SessionItem");
            SessionItem sessionItem = this.sessionService.getSessionByAccessToken(accessToken);

            if (sessionItem == null) {
                throw new SessionItemNotFoundException(
                        "Unable to locate SessionItem with AccessToken");
            }

            if (sessionItem.getSessionId() == null) {
                throw new SessionItemNotFoundException(
                        "SessionItem sessionId does not have a value");
            }

            LOGGER.info("Extracted session from session store ID {}", sessionItem.getSessionId());
            LOGGER.info(
                    "Persistent Logging keys now attached to sessionId {}",
                    sessionItem.getSessionId());

            LOGGER.info("Retrieving PersonIdentityDetailed");
            PersonIdentityDetailed personIdentityDetailed =
                    retrievePersonIdentityDetailed(sessionItem);
            LOGGER.info("PersonIdentityDetailed Retrieved");

            LOGGER.info("Retrieving DocumentCheckResultItem");
            DocumentCheckResultItem documentCheckResultItem =
                    retrieveDocumentCheckResultItem(sessionItem);
            LOGGER.info("DocumentCheckResultItem Retrieved");

            LOGGER.info("All Required VC content retrieved.");

            LOGGER.info("Generating verifiable credential...");
            SignedJWT signedJWT =
                    verifiableCredentialService.generateSignedVerifiableCredentialJwt(
                            sessionItem.getSubject(),
                            documentCheckResultItem,
                            personIdentityDetailed);
            LOGGER.info("Credential generated");

            sendVCIssuedAuditEvent(
                    input.getHeaders(),
                    sessionItem,
                    personIdentityDetailed,
                    documentCheckResultItem);

            // CI Metric captured here as check lambda can have multiple attempts
            recordCIMetrics(PASSPORT_CI_PREFIX, documentCheckResultItem.getContraIndicators());

            sendCriEndAuditEvent(input.getHeaders(), sessionItem);

            eventProbe.counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_OK);

            return ApiGatewayResponseGenerator.proxyJwtResponse(
                    HttpStatusCode.OK, signedJWT.serialize());
        } catch (SessionItemNotFoundException
                | SessionNotFoundException
                | CredentialRequestException
                | AccessTokenExpiredException
                | SessionExpiredException e) {
            eventProbe.counterMetric(Definitions.LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR);

            LOGGER.error(e.getMessage(), e);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                    new CommonExpressOAuthError(OAuth2Error.ACCESS_DENIED));
        } catch (PersonIdentityDetailedNotFoundException
                | DocumentCheckResultItemNotFoundException e) {
            eventProbe.counterMetric(Definitions.LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR);

            LOGGER.error(e.getMessage(), e);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    OAuth2Error.SERVER_ERROR.getHTTPStatusCode(),
                    new CommonExpressOAuthError(OAuth2Error.SERVER_ERROR));
        } catch (SqsException sqsException) {
            LOGGER.error(
                    LAMBDA_EXCEPTION_ERROR_MESSAGE,
                    context.getFunctionName(),
                    sqsException.getClass());
            eventProbe.counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR);

            LOGGER.debug(sqsException.getMessage(), sqsException);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.INTERNAL_SERVER_ERROR, sqsException.getMessage());
        } catch (AwsServiceException ex) {
            LOGGER.warn(LAMBDA_EXCEPTION_ERROR_MESSAGE, context.getFunctionName(), ex.getClass());
            eventProbe.counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR);

            LOGGER.debug(ex.getMessage(), ex);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.INTERNAL_SERVER_ERROR, ex.awsErrorDetails().errorMessage());
        } catch (ParseException | JOSEException e) {
            LOGGER.error(LAMBDA_EXCEPTION_ERROR_MESSAGE, context.getFunctionName(), e.getClass());
            eventProbe.counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR);

            LOGGER.debug(e.getMessage(), e);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.BAD_REQUEST, ErrorResponse.VERIFIABLE_CREDENTIAL_ERROR);
        } catch (Exception e) {
            // This is where unexpected exceptions will reach (null pointers etc)
            // We should not log unknown exceptions, due to possibility of PII
            LOGGER.error(
                    "Unhandled Exception while handling lambda {} exception {}",
                    context.getFunctionName(),
                    e.getClass());

            LOGGER.debug(e.getMessage(), e);

            eventProbe.counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    private AccessToken validateInputHeaderBearerToken(Map<String, String> headers)
            throws CredentialRequestException, ParseException {
        String token =
                Optional.ofNullable(headers).stream()
                        .flatMap(x -> x.entrySet().stream())
                        .filter(
                                header ->
                                        AUTHORIZATION_HEADER_KEY.equalsIgnoreCase(header.getKey()))
                        .map(Map.Entry::getValue)
                        .findFirst()
                        .orElseThrow(
                                () ->
                                        new CredentialRequestException(
                                                ErrorResponse.MISSING_AUTHORIZATION_HEADER));

        return AccessToken.parse(token, AccessTokenType.BEARER);
    }

    private void recordCIMetrics(String ciRequestPrefix, List<String> contraIndications) {
        for (String ci : contraIndications) {
            eventProbe.counterMetric(ciRequestPrefix + ci);
        }
    }

    private PersonIdentityDetailed retrievePersonIdentityDetailed(SessionItem sessionItem)
            throws PersonIdentityDetailedNotFoundException {
        PersonIdentityDetailed personIdentityDetailed =
                personIdentityService.getPersonIdentityDetailed(sessionItem.getSessionId());

        if (personIdentityDetailed == null) {
            String message =
                    String.format(
                            "A PersonIdentityDetailed was not found for sessionId %s",
                            sessionItem.getSessionId());
            throw new PersonIdentityDetailedNotFoundException(message);
        }
        return personIdentityDetailed;
    }

    private DocumentCheckResultItem retrieveDocumentCheckResultItem(SessionItem sessionItem)
            throws DocumentCheckResultItemNotFoundException {

        DocumentCheckResultItem documentCheckResultItem =
                documentCheckResultStore.getItem(sessionItem.getSessionId().toString());

        if (documentCheckResultItem == null) {
            String message =
                    String.format(
                            "A DocumentCheckResultItem was not found for sessionId %s",
                            sessionItem.getSessionId());
            throw new DocumentCheckResultItemNotFoundException(message);
        }

        return documentCheckResultItem;
    }

    private void sendVCIssuedAuditEvent(
            Map<String, String> headers,
            SessionItem sessionItem,
            PersonIdentityDetailed personIdentityDetailed,
            DocumentCheckResultItem documentCheckResultItem)
            throws SqsException {
        AuditEventType auditEventType = AuditEventType.VC_ISSUED;

        LOGGER.info(AUDIT_EVENT_LOG_FORMAT, auditEventType);

        String verifiableCredentialIssuer =
                commonLibConfigurationService.getVerifiableCredentialIssuer();

        // Needed as personIdentityService.savePersonIdentity creates personIdentityDetailed via
        // shared claims
        PersonIdentityDetailed auditRestricted =
                PersonIdentityDetailedHelperMapper
                        .mapPersonIdentityDetailedAndPassportDataToAuditRestricted(
                                personIdentityDetailed, documentCheckResultItem);

        auditService.sendAuditEvent(
                auditEventType,
                new AuditEventContext(auditRestricted, headers, sessionItem),
                IssueCredentialPassportAuditExtensionUtil.generateVCISSDocumentCheckAuditExtension(
                        verifiableCredentialIssuer, List.of(documentCheckResultItem)));
    }

    private void sendCriEndAuditEvent(Map<String, String> headers, SessionItem sessionItem)
            throws SqsException {
        AuditEventType auditEventType = AuditEventType.END;

        LOGGER.info(AUDIT_EVENT_LOG_FORMAT, auditEventType);
        auditService.sendAuditEvent(
                AuditEventType.END, new AuditEventContext(headers, sessionItem));
    }
}
