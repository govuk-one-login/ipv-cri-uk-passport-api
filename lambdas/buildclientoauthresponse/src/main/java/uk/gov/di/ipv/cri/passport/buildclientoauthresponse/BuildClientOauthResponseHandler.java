package uk.gov.di.ipv.cri.passport.buildclientoauthresponse;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.State;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.CorrelationIdPathConstants;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventUser;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.error.CommonExpressOAuthError;
import uk.gov.di.ipv.cri.passport.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.cri.passport.library.exceptions.SqsException;
import uk.gov.di.ipv.cri.passport.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.library.helpers.LogHelper;
import uk.gov.di.ipv.cri.passport.library.helpers.RequestHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportSessionItem;
import uk.gov.di.ipv.cri.passport.library.service.AuditService;
import uk.gov.di.ipv.cri.passport.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.library.service.PassportSessionService;

import java.net.URISyntaxException;

import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_BUILD_CLIENT_OAUTH_RESPONSE_COMPLETED_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_BUILD_CLIENT_OAUTH_RESPONSE_COMPLETED_OK;

public class BuildClientOauthResponseHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final AuthorizationCodeService authorizationCodeService;
    private final PassportSessionService passportSessionService;
    private final AuditService auditService;
    private final ConfigurationService configurationService;
    private final EventProbe eventProbe;

    public BuildClientOauthResponseHandler(
            AuthorizationCodeService authorizationCodeService,
            PassportSessionService passportSessionService,
            AuditService auditService,
            ConfigurationService configurationService,
            EventProbe eventProbe) {
        this.authorizationCodeService = authorizationCodeService;
        this.passportSessionService = passportSessionService;
        this.auditService = auditService;
        this.configurationService = configurationService;
        this.eventProbe = eventProbe;
    }

    public BuildClientOauthResponseHandler() {
        this.configurationService = new ConfigurationService();
        this.authorizationCodeService = new AuthorizationCodeService(configurationService);
        this.passportSessionService = new PassportSessionService(configurationService);
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
        this.eventProbe = new EventProbe();
    }

    @Override
    @Logging(clearState = true, correlationIdPath = CorrelationIdPathConstants.API_GATEWAY_REST)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();

        try {
            String passportSessionId = RequestHelper.getPassportSessionId(input);

            PassportSessionItem passportSessionItem =
                    passportSessionService.getPassportSession(passportSessionId);
            AuditEventUser auditEventUser =
                    AuditEventUser.fromPassportSessionItem(passportSessionItem);

            LogHelper.attachGovukSigninJourneyIdToLogs(
                    passportSessionItem.getGovukSigninJourneyId());

            // It is valid to reach here via prove another way with zero (or more) attempts made
            if (passportSessionItem.getAttemptCount() == 0) {

                String customOAuth2ErrorDescription = "No passport details attempt has been made";

                LOGGER.info(
                        "{} {}", customOAuth2ErrorDescription, "returning Access Denied response");

                auditService.sendAuditEvent(AuditEventTypes.IPV_PASSPORT_CRI_END, auditEventUser);

                // Due to directing prove another way users here - this is not recorded as an error
                // No specific metric added, as this lambda will be replaced with the common auth
                // lambda
                eventProbe.counterMetric(LAMBDA_BUILD_CLIENT_OAUTH_RESPONSE_COMPLETED_OK);

                // CommonExpressOAuthError needed to place the OAuth2Error in the correct place for
                // common-express
                // and ensuring the OAuth2 "error" field matches the OAuth2 standard
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_FORBIDDEN,
                        new CommonExpressOAuthError(
                                OAuth2Error.ACCESS_DENIED, customOAuth2ErrorDescription));
            }

            // TODO - this generates a new authcode but should be fetching the exisiting one.
            // Left as is to avoid a cascade of changes in Session, Auth and Token Services.
            AuthorizationCode authorizationCode =
                    authorizationCodeService.generateAuthorizationCode();

            authorizationCodeService.persistAuthorizationCode(
                    authorizationCode.getValue(), passportSessionId);

            AuthorizationSuccessResponse response =
                    generateAuthorizationSuccessResponse(passportSessionItem, authorizationCode);

            auditService.sendAuditEvent(AuditEventTypes.IPV_PASSPORT_CRI_END, auditEventUser);

            eventProbe.counterMetric(LAMBDA_BUILD_CLIENT_OAUTH_RESPONSE_COMPLETED_OK);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, response);
        } catch (HttpResponseExceptionWithErrorBody e) {
            eventProbe.counterMetric(LAMBDA_BUILD_CLIENT_OAUTH_RESPONSE_COMPLETED_ERROR);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getStatusCode(), e.getErrorResponse());
        } catch (URISyntaxException e) {
            LOGGER.error("Failed to construct redirect uri because: {}", e.getMessage());
            eventProbe.counterMetric(LAMBDA_BUILD_CLIENT_OAUTH_RESPONSE_COMPLETED_ERROR);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        } catch (SqsException e) {
            ErrorObject error = OAuth2Error.SERVER_ERROR.setDescription(e.getMessage());

            LogHelper.logOauthError(
                    "Failed to send message to aws SQS audit event queue",
                    error.getCode(),
                    error.getDescription());

            eventProbe.counterMetric(LAMBDA_BUILD_CLIENT_OAUTH_RESPONSE_COMPLETED_ERROR);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, error.toJSONObject());
        }
    }

    private AuthorizationSuccessResponse generateAuthorizationSuccessResponse(
            PassportSessionItem passportSessionItem, AuthorizationCode authorizationCode)
            throws URISyntaxException {

        URIBuilder redirectUriBuilder =
                new URIBuilder(passportSessionItem.getAuthParams().getRedirectUri());

        redirectUriBuilder.addParameter("response_type", ResponseType.CODE.toString());
        redirectUriBuilder.addParameter("code", authorizationCode.getValue());
        redirectUriBuilder.addParameter("state", passportSessionItem.getAuthParams().getState());
        redirectUriBuilder.addParameter(
                "client_id", passportSessionItem.getAuthParams().getClientId());

        return new AuthorizationSuccessResponse(
                redirectUriBuilder.build(),
                authorizationCode,
                null,
                new State(passportSessionItem.getAuthParams().getState()),
                null);
    }
}
