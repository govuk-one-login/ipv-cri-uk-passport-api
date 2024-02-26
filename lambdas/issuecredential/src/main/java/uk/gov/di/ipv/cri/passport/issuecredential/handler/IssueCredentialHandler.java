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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.CorrelationIdPathConstants;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventContext;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventType;
import uk.gov.di.ipv.cri.common.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.common.library.error.OauthErrorResponse;
import uk.gov.di.ipv.cri.common.library.exception.AccessTokenExpiredException;
import uk.gov.di.ipv.cri.common.library.exception.SessionExpiredException;
import uk.gov.di.ipv.cri.common.library.exception.SessionNotFoundException;
import uk.gov.di.ipv.cri.common.library.exception.SqsException;
import uk.gov.di.ipv.cri.common.library.persistence.DataStore;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.PersonIdentityService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.common.library.util.KMSSigner;
import uk.gov.di.ipv.cri.passport.issuecredential.exception.CredentialRequestException;
import uk.gov.di.ipv.cri.passport.issuecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.cri.passport.issuecredential.util.IssueCredentialPassportAuditExtensionUtil;
import uk.gov.di.ipv.cri.passport.library.error.CommonExpressOAuthError;
import uk.gov.di.ipv.cri.passport.library.helpers.PersonIdentityDetailedHelperMapper;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.cri.common.library.error.ErrorResponse.ACCESS_TOKEN_EXPIRED;
import static uk.gov.di.ipv.cri.common.library.error.ErrorResponse.SESSION_EXPIRED;
import static uk.gov.di.ipv.cri.common.library.error.ErrorResponse.SESSION_NOT_FOUND;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_ISSUE_CREDENTIAL_COMPLETED_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.PASSPORT_CI_PREFIX;

public class IssueCredentialHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LogManager.getLogger();
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

    public IssueCredentialHandler() {
        // A reference to serviceFactory is not held in this class
        ServiceFactory serviceFactory = new ServiceFactory();

        KMSSigner kmsSigner =
                new KMSSigner(
                        serviceFactory
                                .getCommonLibConfigurationService()
                                .getVerifiableCredentialKmsSigningKeyId(),
                        serviceFactory.getClientFactoryService().getKMSClient());

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
    }

    @Override
    @Logging(correlationIdPath = CorrelationIdPathConstants.API_GATEWAY_REST)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        try {
            LOGGER.info(
                    "Initiating lambda {} version {}",
                    context.getFunctionName(),
                    context.getFunctionVersion());

            LOGGER.info("Validating access token...");
            var accessToken = validateInputHeaderBearerToken(input.getHeaders());
            var sessionItem = this.sessionService.getSessionByAccessToken(accessToken);
            LOGGER.info("Extracted session from session store ID {}", sessionItem.getSessionId());

            LOGGER.info("Retrieving identity details and document check results...");
            var personIdentityDetailed =
                    personIdentityService.getPersonIdentityDetailed(sessionItem.getSessionId());
            DocumentCheckResultItem documentCheckResultItem =
                    documentCheckResultStore.getItem(sessionItem.getSessionId().toString());

            if (documentCheckResultItem == null) {
                LOGGER.error("User has arrived in issue credential without completing check");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        OauthErrorResponse.ACCESS_DENIED_ERROR);
            }
            LOGGER.info("VC content retrieved.");

            LOGGER.info("Generating verifiable credential...");
            SignedJWT signedJWT =
                    verifiableCredentialService.generateSignedVerifiableCredentialJwt(
                            sessionItem.getSubject(),
                            documentCheckResultItem,
                            personIdentityDetailed);
            LOGGER.info("Credential generated");

            String verifiableCredentialIssuer =
                    commonLibConfigurationService.getVerifiableCredentialIssuer();

            // Needed as personIdentityService.savePersonIdentity creates personIdentityDetailed via
            // shared claims
            var auditRestricted =
                    PersonIdentityDetailedHelperMapper
                            .mapPersonIdentityDetailedAndPassportDataToAuditRestricted(
                                    personIdentityDetailed, documentCheckResultItem);

            LOGGER.info("Sending audit event {}}...", AuditEventType.VC_ISSUED);
            auditService.sendAuditEvent(
                    AuditEventType.VC_ISSUED,
                    new AuditEventContext(auditRestricted, input.getHeaders(), sessionItem),
                    IssueCredentialPassportAuditExtensionUtil
                            .generateVCISSDocumentCheckAuditExtension(
                                    verifiableCredentialIssuer, List.of(documentCheckResultItem)));

            // CI Metric captured here as check lambda can have multiple attempts
            recordCIMetrics(PASSPORT_CI_PREFIX, documentCheckResultItem.getContraIndicators());

            LOGGER.info("Sending audit event {}...", AuditEventType.END);
            auditService.sendAuditEvent(
                    AuditEventType.END, new AuditEventContext(input.getHeaders(), sessionItem));

            eventProbe.counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_OK);

            return ApiGatewayResponseGenerator.proxyJwtResponse(
                    HttpStatusCode.OK, signedJWT.serialize());
        } catch (SessionNotFoundException e) {

            String customOAuth2ErrorDescription = SESSION_NOT_FOUND.getMessage();
            LOGGER.error(customOAuth2ErrorDescription);
            eventProbe.counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR);

            LOGGER.debug(e.getMessage(), e);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.FORBIDDEN,
                    new CommonExpressOAuthError(
                            OAuth2Error.ACCESS_DENIED, customOAuth2ErrorDescription));
        } catch (SessionExpiredException e) {

            String customOAuth2ErrorDescription = SESSION_EXPIRED.getMessage();
            LOGGER.error(customOAuth2ErrorDescription);
            eventProbe.counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR);

            LOGGER.debug(e.getMessage(), e);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.FORBIDDEN,
                    new CommonExpressOAuthError(
                            OAuth2Error.ACCESS_DENIED, customOAuth2ErrorDescription));
        } catch (AccessTokenExpiredException e) {

            String customOAuth2ErrorDescription = ACCESS_TOKEN_EXPIRED.getMessage();
            LOGGER.error(customOAuth2ErrorDescription);
            eventProbe.counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR);

            LOGGER.debug(e.getMessage(), e);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.FORBIDDEN,
                    new CommonExpressOAuthError(
                            OAuth2Error.ACCESS_DENIED, customOAuth2ErrorDescription));
        } catch (AwsServiceException ex) {
            LOGGER.error(LAMBDA_EXCEPTION_ERROR_MESSAGE, context.getFunctionName(), ex.getClass());
            eventProbe.counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR);

            LOGGER.debug(ex.getMessage(), ex);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.INTERNAL_SERVER_ERROR, ex.awsErrorDetails().errorMessage());
        } catch (CredentialRequestException | ParseException | JOSEException e) {
            LOGGER.error(LAMBDA_EXCEPTION_ERROR_MESSAGE, context.getFunctionName(), e.getClass());
            eventProbe.counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR);

            LOGGER.debug(e.getMessage(), e);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.BAD_REQUEST, ErrorResponse.VERIFIABLE_CREDENTIAL_ERROR);
        } catch (SqsException sqsException) {
            LOGGER.error(
                    LAMBDA_EXCEPTION_ERROR_MESSAGE,
                    context.getFunctionName(),
                    sqsException.getClass());
            eventProbe.counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR);

            LOGGER.debug(sqsException.getMessage(), sqsException);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.INTERNAL_SERVER_ERROR, sqsException.getMessage());
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
        var token =
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
}
