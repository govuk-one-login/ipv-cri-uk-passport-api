package uk.gov.di.ipv.cri.passport.issuecredential.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.awssdk.http.SdkHttpResponse;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventContext;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventType;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.PersonIdentityDetailed;
import uk.gov.di.ipv.cri.common.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.common.library.exception.SqsException;
import uk.gov.di.ipv.cri.common.library.persistence.DataStore;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.PersonIdentityService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.issuecredential.domain.audit.VCISSDocumentCheckAuditExtension;
import uk.gov.di.ipv.cri.passport.issuecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.cri.passport.library.DocumentCheckTestDataGenerator;
import uk.gov.di.ipv.cri.passport.library.PassportFormTestDataGenerator;
import uk.gov.di.ipv.cri.passport.library.helpers.PersonIdentityDetailedHelperMapper;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_ISSUE_CREDENTIAL_COMPLETED_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_ISSUE_CREDENTIAL_FUNCTION_INIT_DURATION;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.PASSPORT_CI_PREFIX;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class IssueCredentialHandlerTest {
    @SystemStub private EnvironmentVariables environmentVariables = new EnvironmentVariables();

    public static final String REQUEST_SUBJECT = "subject";

    @Mock private Context mockLambdaContext;

    @Mock private ServiceFactory mockServiceFactory;

    @Mock private EventProbe mockEventProbe;
    @Mock private ConfigurationService mockCommonLibConfigurationService;
    @Mock private SessionService mockSessionService;
    @Mock private AuditService mockAuditService;
    @Mock private PersonIdentityService mockPersonIdentityService;
    @Mock private DataStore<DocumentCheckResultItem> mockDocumentCheckResultStore;

    // Issue Credential only services
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;

    private IssueCredentialHandler issueCredentialHandler;

    @BeforeEach
    void setup() {
        environmentVariables.set("AWS_REGION", "eu-west-2");
        environmentVariables.set("AWS_STACK_NAME", "TEST_STACK");

        mockServiceFactoryBehaviour();

        this.issueCredentialHandler =
                new IssueCredentialHandler(mockServiceFactory, mockVerifiableCredentialService);
    }

    @Test
    void shouldReturn200OkWhenIssueCredentialRequestIsValid()
            throws JOSEException, SqsException, NoSuchAlgorithmException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        event.withHeaders(
                Map.of(
                        IssueCredentialHandler.AUTHORIZATION_HEADER_KEY,
                        accessToken.toAuthorizationHeader()));
        setRequestBodyAsPlainJWT(event);

        PersonIdentityDetailed personIdentityDetailed =
                PersonIdentityDetailedHelperMapper.passportFormDataToAuditRestrictedFormat(
                        PassportFormTestDataGenerator.generate());
        SessionItem sessionItem = new SessionItem();
        sessionItem.setSessionId(UUID.randomUUID());
        DocumentCheckResultItem resultItem =
                DocumentCheckTestDataGenerator.generateUnverifiedResultItem();

        when(mockSessionService.getSessionByAccessToken(accessToken)).thenReturn(sessionItem);
        when(mockPersonIdentityService.getPersonIdentityDetailed(sessionItem.getSessionId()))
                .thenReturn(personIdentityDetailed);
        when(mockDocumentCheckResultStore.getItem(String.valueOf(sessionItem.getSessionId())))
                .thenReturn(resultItem);
        when(mockVerifiableCredentialService.generateSignedVerifiableCredentialJwt(
                        sessionItem.getSubject(), resultItem, personIdentityDetailed))
                .thenReturn(mock(SignedJWT.class));

        doNothing()
                .when(mockAuditService)
                .sendAuditEvent(
                        eq(AuditEventType.VC_ISSUED),
                        any(AuditEventContext.class),
                        any(VCISSDocumentCheckAuditExtension.class));

        when(mockLambdaContext.getFunctionName()).thenReturn("functionName");
        when(mockLambdaContext.getFunctionVersion()).thenReturn("1.0");
        APIGatewayProxyResponseEvent responseEvent =
                issueCredentialHandler.handleRequest(event, mockLambdaContext);

        verify(mockSessionService).getSessionByAccessToken(accessToken);
        verify(mockDocumentCheckResultStore).getItem(String.valueOf(sessionItem.getSessionId()));
        verify(mockPersonIdentityService).getPersonIdentityDetailed(any());
        verify(mockVerifiableCredentialService)
                .generateSignedVerifiableCredentialJwt(
                        sessionItem.getSubject(), resultItem, personIdentityDetailed);

        InOrder inOrder = inOrder(mockEventProbe, mockAuditService);
        inOrder.verify(mockEventProbe)
                .counterMetric(eq(LAMBDA_ISSUE_CREDENTIAL_FUNCTION_INIT_DURATION), anyDouble());
        inOrder.verify(mockAuditService)
                .sendAuditEvent(
                        eq(AuditEventType.VC_ISSUED),
                        any(AuditEventContext.class),
                        any(VCISSDocumentCheckAuditExtension.class));
        inOrder.verify(mockEventProbe)
                .counterMetric(PASSPORT_CI_PREFIX + resultItem.getContraIndicators().get(0));
        inOrder.verify(mockAuditService)
                .sendAuditEvent(eq(AuditEventType.END), any(AuditEventContext.class));
        inOrder.verify(mockEventProbe).counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_OK);
        verifyNoMoreInteractions(mockEventProbe);
        verifyNoMoreInteractions(mockAuditService);

        assertEquals(
                ContentType.APPLICATION_JWT.getType(),
                responseEvent.getHeaders().get("Content-Type"));
        assertEquals(HttpStatusCode.OK, responseEvent.getStatusCode());
    }

    @Test
    void shouldReturn200OkWhenIssueCredentialRequestIsValidAndIncludeKIdIsTrue()
            throws JOSEException, SqsException, NoSuchAlgorithmException {
        environmentVariables.set("INCLUDE_VC_KID", "true");

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        event.withHeaders(
                Map.of(
                        IssueCredentialHandler.AUTHORIZATION_HEADER_KEY,
                        accessToken.toAuthorizationHeader()));
        setRequestBodyAsPlainJWT(event);

        PersonIdentityDetailed personIdentityDetailed =
                PersonIdentityDetailedHelperMapper.passportFormDataToAuditRestrictedFormat(
                        PassportFormTestDataGenerator.generate());
        SessionItem sessionItem = new SessionItem();
        sessionItem.setSessionId(UUID.randomUUID());
        DocumentCheckResultItem resultItem =
                DocumentCheckTestDataGenerator.generateUnverifiedResultItem();

        when(mockSessionService.getSessionByAccessToken(accessToken)).thenReturn(sessionItem);
        when(mockPersonIdentityService.getPersonIdentityDetailed(sessionItem.getSessionId()))
                .thenReturn(personIdentityDetailed);
        when(mockDocumentCheckResultStore.getItem(String.valueOf(sessionItem.getSessionId())))
                .thenReturn(resultItem);
        when(mockVerifiableCredentialService.generateSignedVerifiableCredentialJwt(
                        sessionItem.getSubject(), resultItem, personIdentityDetailed))
                .thenReturn(mock(SignedJWT.class));

        doNothing()
                .when(mockAuditService)
                .sendAuditEvent(
                        eq(AuditEventType.VC_ISSUED),
                        any(AuditEventContext.class),
                        any(VCISSDocumentCheckAuditExtension.class));

        when(mockLambdaContext.getFunctionName()).thenReturn("functionName");
        when(mockLambdaContext.getFunctionVersion()).thenReturn("1.0");
        APIGatewayProxyResponseEvent responseEvent =
                issueCredentialHandler.handleRequest(event, mockLambdaContext);

        verify(mockSessionService).getSessionByAccessToken(accessToken);
        verify(mockDocumentCheckResultStore).getItem(String.valueOf(sessionItem.getSessionId()));
        verify(mockPersonIdentityService).getPersonIdentityDetailed(any());
        verify(mockVerifiableCredentialService)
                .generateSignedVerifiableCredentialJwt(
                        sessionItem.getSubject(), resultItem, personIdentityDetailed);

        InOrder inOrder = inOrder(mockEventProbe, mockAuditService);
        inOrder.verify(mockEventProbe)
                .counterMetric(eq(LAMBDA_ISSUE_CREDENTIAL_FUNCTION_INIT_DURATION), anyDouble());
        inOrder.verify(mockAuditService)
                .sendAuditEvent(
                        eq(AuditEventType.VC_ISSUED),
                        any(AuditEventContext.class),
                        any(VCISSDocumentCheckAuditExtension.class));
        inOrder.verify(mockEventProbe)
                .counterMetric(PASSPORT_CI_PREFIX + resultItem.getContraIndicators().get(0));
        inOrder.verify(mockAuditService)
                .sendAuditEvent(eq(AuditEventType.END), any(AuditEventContext.class));
        inOrder.verify(mockEventProbe).counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_OK);
        verifyNoMoreInteractions(mockEventProbe);
        verifyNoMoreInteractions(mockAuditService);

        assertEquals(
                ContentType.APPLICATION_JWT.getType(),
                responseEvent.getHeaders().get("Content-Type"));
        assertEquals(HttpStatusCode.OK, responseEvent.getStatusCode());
    }

    @Test
    void shouldThrowJOSEExceptionWhenGenerateVerifiableCredentialIsMalformed()
            throws JOSEException, SqsException, JsonProcessingException, NoSuchAlgorithmException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        event.withHeaders(
                Map.of(
                        IssueCredentialHandler.AUTHORIZATION_HEADER_KEY,
                        accessToken.toAuthorizationHeader()));
        setRequestBodyAsPlainJWT(event);

        var unExpectedJOSEException = new JOSEException("Unexpected JOSE object type: JWSObject");

        var personIdentityDetailed =
                PersonIdentityDetailedHelperMapper.passportFormDataToAuditRestrictedFormat(
                        PassportFormTestDataGenerator.generate());

        SessionItem sessionItem = new SessionItem();
        DocumentCheckResultItem resultItem =
                DocumentCheckTestDataGenerator.generateUnverifiedResultItem();

        when(mockSessionService.getSessionByAccessToken(accessToken)).thenReturn(sessionItem);
        when(mockPersonIdentityService.getPersonIdentityDetailed(any()))
                .thenReturn(personIdentityDetailed);
        when(mockDocumentCheckResultStore.getItem(String.valueOf(sessionItem.getSessionId())))
                .thenReturn(resultItem);
        when(mockVerifiableCredentialService.generateSignedVerifiableCredentialJwt(
                        sessionItem.getSubject(), resultItem, personIdentityDetailed))
                .thenThrow(unExpectedJOSEException);

        APIGatewayProxyResponseEvent response =
                issueCredentialHandler.handleRequest(event, mockLambdaContext);

        verify(mockSessionService).getSessionByAccessToken(accessToken);
        verify(mockDocumentCheckResultStore).getItem(String.valueOf(sessionItem.getSessionId()));
        verify(mockPersonIdentityService).getPersonIdentityDetailed(any());
        verify(mockVerifiableCredentialService)
                .generateSignedVerifiableCredentialJwt(
                        sessionItem.getSubject(), resultItem, personIdentityDetailed);

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe)
                .counterMetric(eq(LAMBDA_ISSUE_CREDENTIAL_FUNCTION_INIT_DURATION), anyDouble());
        inOrder.verify(mockEventProbe).counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR);
        verifyNoMoreInteractions(mockEventProbe);
        verifyNoMoreInteractions(mockAuditService);

        // There is a CI in the test result, we check we do not record CI metrics for a VC
        // generation Error
        verify(mockEventProbe, never())
                .counterMetric(PASSPORT_CI_PREFIX + resultItem.getContraIndicators().get(0));
        verifyNoMoreInteractions(mockVerifiableCredentialService);
        verify(mockAuditService, never())
                .sendAuditEvent(
                        eq(AuditEventType.VC_ISSUED),
                        any(AuditEventContext.class),
                        any(VCISSDocumentCheckAuditExtension.class));
        Map responseBody = new ObjectMapper().readValue(response.getBody(), Map.class);
        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
        assertEquals(
                uk.gov.di.ipv.cri.common.library.error.ErrorResponse.VERIFIABLE_CREDENTIAL_ERROR
                        .getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.VERIFIABLE_CREDENTIAL_ERROR.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldThrowCredentialRequestExceptionWhenAuthorizationHeaderIsNotSupplied()
            throws SqsException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        APIGatewayProxyResponseEvent response =
                issueCredentialHandler.handleRequest(event, mockLambdaContext);

        verify(mockAuditService, never())
                .sendAuditEvent(
                        eq(AuditEventType.VC_ISSUED),
                        any(AuditEventContext.class),
                        any(VCISSDocumentCheckAuditExtension.class));

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe)
                .counterMetric(eq(LAMBDA_ISSUE_CREDENTIAL_FUNCTION_INIT_DURATION), anyDouble());
        inOrder.verify(mockEventProbe).counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR);
        verifyNoMoreInteractions(mockEventProbe);

        assertEquals(
                ContentType.APPLICATION_JSON.getType(), response.getHeaders().get("Content-Type"));
        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    void shouldThrowAWSExceptionWhenAServerErrorOccursRetrievingASessionItemWithAccessToken()
            throws JsonProcessingException, SqsException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        event.withHeaders(
                Map.of(
                        IssueCredentialHandler.AUTHORIZATION_HEADER_KEY,
                        accessToken.toAuthorizationHeader()));

        setRequestBodyAsPlainJWT(event);

        AwsErrorDetails awsErrorDetails =
                AwsErrorDetails.builder()
                        .errorCode("")
                        .sdkHttpResponse(
                                SdkHttpResponse.builder()
                                        .statusCode(HttpStatusCode.INTERNAL_SERVER_ERROR)
                                        .build())
                        .errorMessage("AWS DynamoDbException Occurred")
                        .build();

        when(mockSessionService.getSessionByAccessToken(accessToken))
                .thenThrow(
                        AwsServiceException.builder()
                                .statusCode(500)
                                .awsErrorDetails(awsErrorDetails)
                                .build());

        APIGatewayProxyResponseEvent response =
                issueCredentialHandler.handleRequest(event, mockLambdaContext);

        verify(mockSessionService).getSessionByAccessToken(accessToken);
        verify(mockPersonIdentityService, never()).getPersonIdentityDetailed(any(UUID.class));
        verify(mockAuditService, never())
                .sendAuditEvent(
                        eq(AuditEventType.VC_ISSUED),
                        any(AuditEventContext.class),
                        any(VCISSDocumentCheckAuditExtension.class));
        verify(mockAuditService, never()).sendAuditEvent((AuditEventType) any());

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe)
                .counterMetric(eq(LAMBDA_ISSUE_CREDENTIAL_FUNCTION_INIT_DURATION), anyDouble());
        inOrder.verify(mockEventProbe).counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR);
        verifyNoMoreInteractions(mockEventProbe);
        verifyNoMoreInteractions(mockAuditService);

        String responseBody = new ObjectMapper().readValue(response.getBody(), String.class);
        assertEquals(awsErrorDetails.sdkHttpResponse().statusCode(), response.getStatusCode());
        assertEquals(awsErrorDetails.errorMessage(), responseBody);
    }

    @Test
    void shouldThrowAWSExceptionWhenAServerErrorOccursDuringRetrievingPersonIdentityWithSessionId()
            throws JsonProcessingException, SqsException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        event.withHeaders(
                Map.of(
                        IssueCredentialHandler.AUTHORIZATION_HEADER_KEY,
                        accessToken.toAuthorizationHeader()));

        setRequestBodyAsPlainJWT(event);

        AwsErrorDetails awsErrorDetails =
                AwsErrorDetails.builder()
                        .errorCode("")
                        .sdkHttpResponse(
                                SdkHttpResponse.builder()
                                        .statusCode(HttpStatusCode.INTERNAL_SERVER_ERROR)
                                        .build())
                        .errorMessage("AWS DynamoDbException Occurred")
                        .build();

        SessionItem sessionItem = new SessionItem();
        when(mockSessionService.getSessionByAccessToken(accessToken)).thenReturn(sessionItem);
        when(mockPersonIdentityService.getPersonIdentityDetailed(sessionItem.getSessionId()))
                .thenThrow(
                        AwsServiceException.builder()
                                .statusCode(500)
                                .awsErrorDetails(awsErrorDetails)
                                .build());

        APIGatewayProxyResponseEvent response =
                issueCredentialHandler.handleRequest(event, mockLambdaContext);

        verify(mockSessionService).getSessionByAccessToken(accessToken);
        verify(mockPersonIdentityService).getPersonIdentityDetailed(sessionItem.getSessionId());
        verify(mockAuditService, never())
                .sendAuditEvent(
                        eq(AuditEventType.VC_ISSUED),
                        any(AuditEventContext.class),
                        any(VCISSDocumentCheckAuditExtension.class));
        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe)
                .counterMetric(eq(LAMBDA_ISSUE_CREDENTIAL_FUNCTION_INIT_DURATION), anyDouble());
        inOrder.verify(mockEventProbe).counterMetric(LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR);
        verifyNoMoreInteractions(mockEventProbe);
        verifyNoMoreInteractions(mockAuditService);

        String responseBody = new ObjectMapper().readValue(response.getBody(), String.class);
        assertEquals(awsErrorDetails.sdkHttpResponse().statusCode(), response.getStatusCode());
        assertEquals(awsErrorDetails.errorMessage(), responseBody);
    }

    private void setRequestBodyAsPlainJWT(APIGatewayProxyRequestEvent event) {
        String requestJWT =
                new PlainJWT(
                                new JWTClaimsSet.Builder()
                                        .claim(JWTClaimNames.SUBJECT, REQUEST_SUBJECT)
                                        .build())
                        .serialize();

        event.setBody(requestJWT);
    }

    private void mockServiceFactoryBehaviour() {
        when(mockServiceFactory.getEventProbe()).thenReturn(mockEventProbe);

        when(mockServiceFactory.getCommonLibConfigurationService())
                .thenReturn(mockCommonLibConfigurationService);

        when(mockServiceFactory.getSessionService()).thenReturn(mockSessionService);
        when(mockServiceFactory.getAuditService()).thenReturn(mockAuditService);

        when(mockServiceFactory.getPersonIdentityService()).thenReturn(mockPersonIdentityService);

        when(mockServiceFactory.getDocumentCheckResultStore())
                .thenReturn(mockDocumentCheckResultStore);
    }
}
