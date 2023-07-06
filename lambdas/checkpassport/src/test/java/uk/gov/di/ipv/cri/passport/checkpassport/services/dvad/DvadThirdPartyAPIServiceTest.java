package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.APIResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.AccessTokenResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.Errors;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.Extensions;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.ResponseData;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.ValidatePassportData;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.ValidationResult;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.ThirdPartyAPIResult;
import uk.gov.di.ipv.cri.passport.checkpassport.services.ThirdPartyAPIService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints.DvadAPIEndpointFactory;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints.GraphQLRequestService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints.HealthCheckService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints.TokenRequestService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.util.dvad.responses.ResponseDataGenerator;
import uk.gov.di.ipv.cri.passport.library.PassportFormTestDataGenerator;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_API_KEY;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_AUDIENCE;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_CLIENT_ID;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_GRANT_TYPE;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_SECRET;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_USER_AGENT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_GRAPHQL_QUERY_STRING;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_INVALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_VALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_INVALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_VALID;

@ExtendWith(MockitoExtension.class)
class DvadThirdPartyAPIServiceTest {

    private ObjectMapper realObjectMapper;

    @Mock private EventProbe mockEventProbe;

    @Mock private CloseableHttpClient mockCloseableHttpClient;

    @Mock private PassportConfigurationService mockPassportConfigurationService;

    @Mock private DvadAPIEndpointFactory mockDvadAPIEndpointFactory;
    @Mock private HealthCheckService mockHealthCheckService;
    @Mock private TokenRequestService mockTokenRequestService;
    @Mock private GraphQLRequestService mockGraphQLRequestService;

    private ThirdPartyAPIService dvadThirdPartyAPIServiceTest;

    @BeforeEach
    void setUp() {
        realObjectMapper = new ObjectMapper();

        // Mocks out the creation of all endpoints to allow mocking the endpoint responses without
        // calling them for real
        when(mockDvadAPIEndpointFactory.createHealthCheckService(
                        eq(mockCloseableHttpClient),
                        any(RequestConfig.class),
                        eq(realObjectMapper),
                        eq(mockEventProbe)))
                .thenReturn(mockHealthCheckService);

        when(mockDvadAPIEndpointFactory.createTokenRequestService(
                        eq(mockCloseableHttpClient),
                        any(RequestConfig.class),
                        eq(realObjectMapper),
                        eq(mockEventProbe)))
                .thenReturn(mockTokenRequestService);

        when(mockDvadAPIEndpointFactory.createGraphQLRequestService(
                        eq(mockCloseableHttpClient),
                        any(RequestConfig.class),
                        eq(realObjectMapper),
                        eq(mockEventProbe)))
                .thenReturn(mockGraphQLRequestService);

        dvadThirdPartyAPIServiceTest =
                new DvadThirdPartyAPIService(
                        mockDvadAPIEndpointFactory,
                        mockPassportConfigurationService,
                        mockEventProbe,
                        mockCloseableHttpClient,
                        realObjectMapper);
    }

    /*
    ****************************************************************************************************
       Happy Path All Endpoints Succeed (Found/Not found User)
    ***************************************************************************************************** */

    @ParameterizedTest
    @CsvSource({
        "true, SUCCESS", // API response found
        "false, FAILURE" // API response not found
    })
    void shouldReturnIsValidTrueGivenValidDataAndAllThirdPartyEndpointsRespond(
            boolean passportFound, ValidationResult validationResult)
            throws OAuthErrorResponseException, IOException {

        boolean expectedIsValid = (passportFound && validationResult == ValidationResult.SUCCESS);

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();

        // Health service Response
        boolean testHealthCheckStatusUp = true;

        // Token service Response
        AccessTokenResponse testValidAccessTokenResponse =
                AccessTokenResponse.builder()
                        .accessToken("A_TOKEN_VALUE")
                        .tokenType("Bearer")
                        .expiresIn(1800)
                        .build();

        // Generated a valid api response object to create the api response for this test
        APIResponse testAPIResponseObject;

        if (expectedIsValid) {
            testAPIResponseObject =
                    APIResponse.builder()
                            .data(ResponseDataGenerator.createValidSuccessResponseData())
                            .build();
        } else {
            testAPIResponseObject =
                    APIResponse.builder()
                            .data(ResponseDataGenerator.createValidNotFoundResponseData())
                            .build();
        }

        String testApiResultString = realObjectMapper.writeValueAsString(testAPIResponseObject);

        mockDvadAPIHeaderValues();

        when(mockHealthCheckService.checkRemoteApiIsUp(
                        any(String.class), any(DvadAPIHeaderValues.class)))
                .thenReturn(testHealthCheckStatusUp);

        when(mockTokenRequestService.requestAccessToken(
                        any(String.class), any(DvadAPIHeaderValues.class)))
                .thenReturn(testValidAccessTokenResponse);

        final String TEST_QUERY_STRING = "TEST_QUERY_STRING";
        when(mockPassportConfigurationService.getEncryptedSsmParameter(HMPO_GRAPHQL_QUERY_STRING))
                .thenReturn(TEST_QUERY_STRING);

        when(mockGraphQLRequestService.performGraphQLQuery(
                        any(String.class),
                        eq(testValidAccessTokenResponse),
                        any(DvadAPIHeaderValues.class),
                        eq(TEST_QUERY_STRING),
                        eq(passportFormData)))
                .thenReturn(testApiResultString);

        ThirdPartyAPIResult result = dvadThirdPartyAPIServiceTest.performCheck(passportFormData);

        // Using the correct third party API?
        assertEquals(
                dvadThirdPartyAPIServiceTest.getServiceName(),
                DvadThirdPartyAPIService.class.getSimpleName());

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe)
                .counterMetric(DVAD_TOKEN_RESPONSE_TYPE_VALID.withEndpointPrefix());
        inOrder.verify(mockEventProbe)
                .counterMetric(DVAD_GRAPHQL_RESPONSE_TYPE_VALID.withEndpointPrefix());
        verifyNoMoreInteractions(mockEventProbe);

        assertNotNull(result);
        assertNotNull(result.getTransactionId());
        assertNotNull(result.getFlags());

        assertEquals(expectedIsValid, result.isValid());
    }

    @ParameterizedTest
    @CsvSource({
        "true", // API response contains errors list
        "false" // API response is empty (invalid)
    })
    void shouldThrowOAuthErrorResponseExceptionWhenAPIResponseContainsErrorsOrIsEmpty(
            boolean errors) throws OAuthErrorResponseException, IOException {

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();

        // Health service Response
        boolean testHealthCheckStatusUp = true;

        // Token service Response
        AccessTokenResponse testValidAccessTokenResponse =
                AccessTokenResponse.builder()
                        .accessToken("A_TOKEN_VALUE")
                        .tokenType("Bearer")
                        .expiresIn(1800)
                        .build();

        // Generated a valid api response object to create the api response for this test
        APIResponse testAPIResponseObject;

        List<Errors> errorsList =
                List.of(
                        new Errors(
                                "Provided data for Field1 is not possible", new Extensions("001")),
                        new Errors(
                                "Provided data for Field2 is not possible", new Extensions("002")));

        if (errors) {
            testAPIResponseObject = APIResponse.builder().errors(errorsList).build();
        } else {
            testAPIResponseObject = APIResponse.builder().build();
        }

        String testApiResultString = realObjectMapper.writeValueAsString(testAPIResponseObject);

        mockDvadAPIHeaderValues();

        when(mockHealthCheckService.checkRemoteApiIsUp(
                        any(String.class), any(DvadAPIHeaderValues.class)))
                .thenReturn(testHealthCheckStatusUp);

        when(mockTokenRequestService.requestAccessToken(
                        any(String.class), any(DvadAPIHeaderValues.class)))
                .thenReturn(testValidAccessTokenResponse);

        final String TEST_QUERY_STRING = "TEST_QUERY_STRING";
        when(mockPassportConfigurationService.getEncryptedSsmParameter(HMPO_GRAPHQL_QUERY_STRING))
                .thenReturn(TEST_QUERY_STRING);

        when(mockGraphQLRequestService.performGraphQLQuery(
                        any(String.class),
                        eq(testValidAccessTokenResponse),
                        any(DvadAPIHeaderValues.class),
                        eq(TEST_QUERY_STRING),
                        eq(passportFormData)))
                .thenReturn(testApiResultString);

        ErrorResponse errorResponse =
                errors
                        ? ErrorResponse.GRAPHQL_ENDPOINT_RETURNED_AN_ERROR_RESPONSE
                        : ErrorResponse.DVAD_API_RESPONSE_NOT_VALID;

        OAuthErrorResponseException expectedReturnedException =
                new OAuthErrorResponseException(HttpStatus.SC_INTERNAL_SERVER_ERROR, errorResponse);

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () -> dvadThirdPartyAPIServiceTest.performCheck(passportFormData),
                        "Expected OAuthErrorResponseException");

        assertEquals(
                dvadThirdPartyAPIServiceTest.getServiceName(),
                DvadThirdPartyAPIService.class.getSimpleName());

        InOrder inOrder = inOrder(mockEventProbe);
        if (errors) {
            inOrder.verify(mockEventProbe)
                    .counterMetric(DVAD_TOKEN_RESPONSE_TYPE_VALID.withEndpointPrefix());
            inOrder.verify(mockEventProbe)
                    .counterMetric(DVAD_GRAPHQL_RESPONSE_TYPE_ERROR.withEndpointPrefix());
        } else {
            inOrder.verify(mockEventProbe)
                    .counterMetric(DVAD_TOKEN_RESPONSE_TYPE_VALID.withEndpointPrefix());
            inOrder.verify(mockEventProbe)
                    .counterMetric(DVAD_GRAPHQL_RESPONSE_TYPE_INVALID.withEndpointPrefix());
        }
        verifyNoMoreInteractions(mockEventProbe);

        assertEquals(expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        assertEquals(expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
    }

    @Test
    void shouldReturnOAuthErrorResponseExceptionWhenHealthEndpointIsDown()
            throws OAuthErrorResponseException {

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();

        boolean testHealthCheckStatusUp = false;

        mockDvadAPIHeaderValues();

        when(mockHealthCheckService.checkRemoteApiIsUp(
                        any(String.class), any(DvadAPIHeaderValues.class)))
                .thenReturn(testHealthCheckStatusUp);

        OAuthErrorResponseException expectedReturnedException =
                new OAuthErrorResponseException(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.ERROR_THIRD_PARTY_API_HEALTH_ENDPOINT_NOT_UP);

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () -> dvadThirdPartyAPIServiceTest.performCheck(passportFormData),
                        "Expected OAuthErrorResponseException");

        assertEquals(expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        assertEquals(expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
    }

    @ParameterizedTest
    @CsvSource({
        // TokenType, expiresIn
        "BAD_TOKEN_TYPE, 1800", // Bad type
        "Bearer, 0", // expiry short
        "Bearer, 1801", // bad expiry long
    })
    void shouldReturnOAuthErrorResponseExceptionWhenTokenTypeIsInvalid(
            String tokenType, long expiresIn) throws OAuthErrorResponseException {

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();

        // Health service Response
        boolean testHealthCheckStatusUp = true;

        // Token service Response
        AccessTokenResponse testInvalidAccessTokenResponse =
                AccessTokenResponse.builder()
                        .accessToken("A_TOKEN_VALUE")
                        .tokenType(tokenType)
                        .expiresIn(expiresIn)
                        .build();

        mockDvadAPIHeaderValues();

        when(mockHealthCheckService.checkRemoteApiIsUp(
                        any(String.class), any(DvadAPIHeaderValues.class)))
                .thenReturn(testHealthCheckStatusUp);

        when(mockTokenRequestService.requestAccessToken(
                        any(String.class), any(DvadAPIHeaderValues.class)))
                .thenReturn(testInvalidAccessTokenResponse);

        OAuthErrorResponseException expectedReturnedException =
                new OAuthErrorResponseException(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_VERIFY_ACCESS_TOKEN);

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () -> dvadThirdPartyAPIServiceTest.performCheck(passportFormData),
                        "Expected OAuthErrorResponseException");

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe)
                .counterMetric(DVAD_TOKEN_RESPONSE_TYPE_INVALID.withEndpointPrefix());
        inOrder.verify(mockEventProbe, never())
                .counterMetric(DVAD_GRAPHQL_RESPONSE_TYPE_VALID.withEndpointPrefix());
        inOrder.verify(mockEventProbe, never())
                .counterMetric(DVAD_GRAPHQL_RESPONSE_TYPE_INVALID.withEndpointPrefix());
        inOrder.verify(mockEventProbe, never())
                .counterMetric(DVAD_GRAPHQL_RESPONSE_TYPE_ERROR.withEndpointPrefix());
        verifyNoMoreInteractions(mockEventProbe);

        assertEquals(expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        assertEquals(expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
    }

    @Test
    void shouldReturnOAuthErrorResponseExceptionWhenGraphQLResponseCannotBeMapped()
            throws OAuthErrorResponseException {

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();

        // Health service Response
        boolean testHealthCheckStatusUp = true;

        // Token service Response
        AccessTokenResponse testValidAccessTokenResponse =
                AccessTokenResponse.builder()
                        .accessToken("A_TOKEN_VALUE")
                        .tokenType("Bearer")
                        .expiresIn(1800)
                        .build();

        mockDvadAPIHeaderValues();

        when(mockHealthCheckService.checkRemoteApiIsUp(
                        any(String.class), any(DvadAPIHeaderValues.class)))
                .thenReturn(testHealthCheckStatusUp);

        when(mockTokenRequestService.requestAccessToken(
                        any(String.class), any(DvadAPIHeaderValues.class)))
                .thenReturn(testValidAccessTokenResponse);

        when(mockPassportConfigurationService.getEncryptedSsmParameter(HMPO_GRAPHQL_QUERY_STRING))
                .thenReturn("Select * from PassportDB where passport.id=");

        when(mockGraphQLRequestService.performGraphQLQuery(
                        any(String.class),
                        any(AccessTokenResponse.class),
                        any(DvadAPIHeaderValues.class),
                        any(String.class),
                        eq(passportFormData)))
                .thenReturn("BAD RESPONSE DATA");

        OAuthErrorResponseException expectedReturnedException =
                new OAuthErrorResponseException(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_MAP_GRAPHQL_ENDPOINT_RESPONSE_BODY);

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () -> dvadThirdPartyAPIServiceTest.performCheck(passportFormData),
                        "Expected OAuthErrorResponseException");

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe)
                .counterMetric(DVAD_TOKEN_RESPONSE_TYPE_VALID.withEndpointPrefix());
        inOrder.verify(mockEventProbe)
                .counterMetric(DVAD_GRAPHQL_RESPONSE_TYPE_INVALID.withEndpointPrefix());
        verifyNoMoreInteractions(mockEventProbe);

        assertEquals(expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        assertEquals(expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
    }

    @ParameterizedTest
    @CsvSource({
        "API Response Data is null",
        "API Response ValidatePassportData is null",
        "API Response ValidationResult is null",
    })
    void shouldReturnOAuthErrorResponseExceptionWhenGraphQLResponseFailsValidation(
            String forcedFailure) throws OAuthErrorResponseException, JsonProcessingException {

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();

        // Health service Response
        boolean testHealthCheckStatusUp = true;

        // Token service Response
        AccessTokenResponse testValidAccessTokenResponse =
                AccessTokenResponse.builder()
                        .accessToken("A_TOKEN_VALUE")
                        .tokenType("Bearer")
                        .expiresIn(1800)
                        .build();

        APIResponse response = null;

        if (forcedFailure.equals("API Response Data is null")) {
            response = APIResponse.builder().data(null).build();
        } else if (forcedFailure.equals("API Response ValidatePassportData is null")) {

            ResponseData responseData = ResponseData.builder().validatePassportData(null).build();
            response = APIResponse.builder().data(responseData).build();

        } else if (forcedFailure.equals("API Response ValidationResult is null")) {

            ValidatePassportData validatePassportData =
                    ValidatePassportData.builder()
                            .validationResult(null)
                            .passportFound(true)
                            .build();

            ResponseData responseData =
                    ResponseData.builder().validatePassportData(validatePassportData).build();
            response = APIResponse.builder().data(responseData).build();
        } else {
            response = null;
        }

        String testResponseBody = realObjectMapper.writeValueAsString(response);

        mockDvadAPIHeaderValues();

        when(mockHealthCheckService.checkRemoteApiIsUp(
                        any(String.class), any(DvadAPIHeaderValues.class)))
                .thenReturn(testHealthCheckStatusUp);

        when(mockTokenRequestService.requestAccessToken(
                        any(String.class), any(DvadAPIHeaderValues.class)))
                .thenReturn(testValidAccessTokenResponse);

        when(mockPassportConfigurationService.getEncryptedSsmParameter(HMPO_GRAPHQL_QUERY_STRING))
                .thenReturn("Select * from PassportDB where passport.id=");

        when(mockGraphQLRequestService.performGraphQLQuery(
                        any(String.class),
                        any(AccessTokenResponse.class),
                        any(DvadAPIHeaderValues.class),
                        any(String.class),
                        eq(passportFormData)))
                .thenReturn(testResponseBody);

        OAuthErrorResponseException expectedReturnedException =
                new OAuthErrorResponseException(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.DVAD_API_RESPONSE_NOT_VALID);

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () -> dvadThirdPartyAPIServiceTest.performCheck(passportFormData),
                        "Expected OAuthErrorResponseException");

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe)
                .counterMetric(DVAD_TOKEN_RESPONSE_TYPE_VALID.withEndpointPrefix());
        inOrder.verify(mockEventProbe)
                .counterMetric(DVAD_GRAPHQL_RESPONSE_TYPE_INVALID.withEndpointPrefix());
        verifyNoMoreInteractions(mockEventProbe);

        assertEquals(expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        assertEquals(expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
    }

    private void mockDvadAPIHeaderValues() {
        when(mockPassportConfigurationService.getEncryptedSsmParameter(HMPO_API_HEADER_API_KEY))
                .thenReturn("TEST_KEY");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_USER_AGENT))
                .thenReturn("TEST_USER_AGENT");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_CLIENT_ID))
                .thenReturn("TEST_CLIENT_ID");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_SECRET))
                .thenReturn("TEST_SECRET");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_GRANT_TYPE))
                .thenReturn("TEST_GRANT_TYPE");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_AUDIENCE))
                .thenReturn("TEST_AUDIENCE");
    }
}
