package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad;

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
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.AccessTokenResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.GraphQLAPIResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.ResponseData;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.errors.Errors;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.ThirdPartyAPIResult;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.dvad.endpoints.GraphQLServiceResult;
import uk.gov.di.ipv.cri.passport.checkpassport.services.ThirdPartyAPIService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints.DvadAPIEndpointFactory;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints.GraphQLRequestService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints.HealthCheckService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints.TokenRequestService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.util.dvad.responses.GraphQLAPIErrorDataGenerator;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.util.dvad.responses.ResponseDataGenerator;
import uk.gov.di.ipv.cri.passport.library.PassportFormTestDataGenerator;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_API_KEY;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_CLIENT_ID;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_GRANT_TYPE;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_NETWORK_TYPE;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_SECRET;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_USER_AGENT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_GRAPHQL_QUERY_STRING;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_INVALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_VALID;

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
        "true", // API response ValidationResult true
        "false" // API response ValidationResult false
    })
    void shouldReturnIsValidTrueGivenValidDataAndAllThirdPartyEndpointsRespond(
            boolean validationResult) throws OAuthErrorResponseException {

        boolean expectedIsValid = validationResult;

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
        GraphQLServiceResult testGraphQLServiceResult;
        GraphQLAPIResponse testGraphQLAPIResponseObject;

        if (expectedIsValid) {
            testGraphQLAPIResponseObject =
                    GraphQLAPIResponse.builder()
                            .data(ResponseDataGenerator.createValidationResultTrueResponseData())
                            .build();
        } else {
            testGraphQLAPIResponseObject =
                    GraphQLAPIResponse.builder()
                            .data(ResponseDataGenerator.createValidationResultFalseResponseData())
                            .build();
        }
        testGraphQLServiceResult =
                GraphQLServiceResult.builder()
                        .graphQLAPIResponse(testGraphQLAPIResponseObject)
                        .requestId(UUID.randomUUID().toString())
                        .build();

        mockDvadAPIHeaderValues();

        when(mockHealthCheckService.checkRemoteApiIsUp(any(DvadAPIHeaderValues.class)))
                .thenReturn(testHealthCheckStatusUp);

        when(mockTokenRequestService.requestAccessToken(any(DvadAPIHeaderValues.class), eq(true)))
                .thenReturn(testValidAccessTokenResponse);

        final String TEST_QUERY_STRING = "TEST_QUERY_STRING";
        when(mockPassportConfigurationService.getEncryptedSsmParameter(HMPO_GRAPHQL_QUERY_STRING))
                .thenReturn(TEST_QUERY_STRING);

        when(mockGraphQLRequestService.performGraphQLQuery(
                        eq(testValidAccessTokenResponse),
                        any(DvadAPIHeaderValues.class),
                        eq(TEST_QUERY_STRING),
                        eq(passportFormData)))
                .thenReturn(testGraphQLServiceResult);

        ThirdPartyAPIResult result = dvadThirdPartyAPIServiceTest.performCheck(passportFormData);

        // Using the correct third party API?
        assertEquals(
                dvadThirdPartyAPIServiceTest.getServiceName(),
                DvadThirdPartyAPIService.class.getSimpleName());

        InOrder inOrder = inOrder(mockEventProbe);
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
            boolean errors) throws OAuthErrorResponseException {

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
        GraphQLServiceResult testGraphQLServiceResult;
        GraphQLAPIResponse testGraphQLAPIResponseObject;

        if (errors) {
            List<Errors> errorsList =
                    List.of(
                            GraphQLAPIErrorDataGenerator.createAPIValidationError("PassportNumber"),
                            GraphQLAPIErrorDataGenerator.createAPIValidationError("IssueDate"));

            testGraphQLAPIResponseObject = GraphQLAPIResponse.builder().errors(errorsList).build();
        } else {
            testGraphQLAPIResponseObject = GraphQLAPIResponse.builder().build();
        }
        testGraphQLServiceResult =
                GraphQLServiceResult.builder()
                        .graphQLAPIResponse(testGraphQLAPIResponseObject)
                        .requestId(UUID.randomUUID().toString())
                        .build();

        mockDvadAPIHeaderValues();

        when(mockHealthCheckService.checkRemoteApiIsUp(any(DvadAPIHeaderValues.class)))
                .thenReturn(testHealthCheckStatusUp);

        when(mockTokenRequestService.requestAccessToken(any(DvadAPIHeaderValues.class), eq(true)))
                .thenReturn(testValidAccessTokenResponse);

        final String TEST_QUERY_STRING = "TEST_QUERY_STRING";
        when(mockPassportConfigurationService.getEncryptedSsmParameter(HMPO_GRAPHQL_QUERY_STRING))
                .thenReturn(TEST_QUERY_STRING);

        when(mockGraphQLRequestService.performGraphQLQuery(
                        eq(testValidAccessTokenResponse),
                        any(DvadAPIHeaderValues.class),
                        eq(TEST_QUERY_STRING),
                        eq(passportFormData)))
                .thenReturn(testGraphQLServiceResult);

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
                    .counterMetric(DVAD_GRAPHQL_RESPONSE_TYPE_ERROR.withEndpointPrefix());
        } else {
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

        when(mockHealthCheckService.checkRemoteApiIsUp(any(DvadAPIHeaderValues.class)))
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
        "API Response Data is null",
        "API Response ValidatePassport is null",
        "API Response ValidatePassport is empty",
        "API Response ValidatePassport is missing validationResult"
    })
    void shouldReturnOAuthErrorResponseExceptionWhenGraphQLResponseFailsValidation(
            String forcedFailure) throws OAuthErrorResponseException {

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

        GraphQLServiceResult testGraphQLServiceResult = null;
        GraphQLAPIResponse testGraphQLAPIResponseObject = null;

        switch (forcedFailure) {
            case "API Response Data is null":
                testGraphQLAPIResponseObject = GraphQLAPIResponse.builder().data(null).build();
                break;
            case "API Response ValidatePassport is null":
                {
                    ResponseData responseData =
                            ResponseData.builder().validatePassport(null).build();
                    testGraphQLAPIResponseObject =
                            GraphQLAPIResponse.builder().data(responseData).build();
                    break;
                }
            case "API Response ValidatePassport is empty":
                {
                    ResponseData responseData =
                            ResponseData.builder().validatePassport(new HashMap<>()).build();
                    testGraphQLAPIResponseObject =
                            GraphQLAPIResponse.builder().data(responseData).build();
                    break;
                }
            case "API Response ValidatePassport is missing validationResult":
                {
                    Map<String, String> testValidatePassportMissingValidationResult =
                            new HashMap<>();
                    testValidatePassportMissingValidationResult.put("Flag", "true");

                    ResponseData responseData =
                            ResponseData.builder()
                                    .validatePassport(testValidatePassportMissingValidationResult)
                                    .build();
                    testGraphQLAPIResponseObject =
                            GraphQLAPIResponse.builder().data(responseData).build();
                    break;
                }
        }
        testGraphQLServiceResult =
                GraphQLServiceResult.builder()
                        .graphQLAPIResponse(testGraphQLAPIResponseObject)
                        .requestId(UUID.randomUUID().toString())
                        .build();

        mockDvadAPIHeaderValues();

        when(mockHealthCheckService.checkRemoteApiIsUp(any(DvadAPIHeaderValues.class)))
                .thenReturn(testHealthCheckStatusUp);

        when(mockTokenRequestService.requestAccessToken(any(DvadAPIHeaderValues.class), eq(true)))
                .thenReturn(testValidAccessTokenResponse);

        when(mockPassportConfigurationService.getEncryptedSsmParameter(HMPO_GRAPHQL_QUERY_STRING))
                .thenReturn("Select * from PassportDB where passport.id=");

        when(mockGraphQLRequestService.performGraphQLQuery(
                        any(AccessTokenResponse.class),
                        any(DvadAPIHeaderValues.class),
                        any(String.class),
                        eq(passportFormData)))
                .thenReturn(testGraphQLServiceResult);

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
                .counterMetric(DVAD_GRAPHQL_RESPONSE_TYPE_INVALID.withEndpointPrefix());
        verifyNoMoreInteractions(mockEventProbe);

        assertEquals(expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        assertEquals(expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
    }

    // Test checks the error line is output correctly from several possible error formats
    // Line format is expect to be "Error : %s%s%s%s%s" where some strings may be empty.
    @ParameterizedTest
    @CsvSource({
        "ClassificationIsString",
        "ClassificationIsObject",
        "MinimalTestCaseError",
        "NullTestCaseError",
        "EmptyTestCaseError"
    })
    void shouldGetErrorLineWhenClassificationIsStringOrObject(String scenario)
            throws NoSuchMethodException {

        Errors errors = GraphQLAPIErrorDataGenerator.createAPIErrorScenario(scenario);

        DvadThirdPartyAPIService spyDvadThirdPartyAPIService;

        // "GetErrorLine" is a private helper method
        // The following uses reflection to unlock the method and confirm its behaviour
        DvadThirdPartyAPIService spyTarget =
                new DvadThirdPartyAPIService(
                        mockDvadAPIEndpointFactory,
                        mockPassportConfigurationService,
                        mockEventProbe,
                        mockCloseableHttpClient,
                        realObjectMapper);

        spyDvadThirdPartyAPIService = spy(spyTarget);

        Method privateGetErrorLine =
                DvadThirdPartyAPIService.class.getDeclaredMethod("getErrorLine", Errors.class);
        privateGetErrorLine.setAccessible(true);

        // Call the private method and capture result
        AtomicReference<String> arErrorLine = new AtomicReference<>();
        assertDoesNotThrow(
                () ->
                        arErrorLine.set(
                                (String)
                                        privateGetErrorLine.invoke(
                                                spyDvadThirdPartyAPIService, errors)));

        String errorLine = arErrorLine.get();
        assertNotNull(errorLine);

        // Error : Message
        String[] errorLineParts = errorLine.split(":", 2);
        assertNotNull(errorLineParts);
        assertEquals(2, errorLineParts.length);

        // Line Prefix
        assertEquals("Error", errorLineParts[0].strip());

        // Get the messageParts
        String[] messageParts = errorLineParts[1].stripLeading().split(", ");
        Map<String, String> messagePartMap = new HashMap<>();
        for (String messagePart : messageParts) {
            String[] messagePartsPart = messagePart.split(" ", 2);
            messagePartMap.put(messagePartsPart[0], messagePartsPart[1]);
        }

        // For anyone extending or updating this
        //  print out ("messagePartMap");
        // print out (messagePartMap.toString());

        // Check the messageParts contents for each scenario
        switch (scenario) {
            case "ClassificationIsString":
                assertClassificationIsStringMessageParts(messagePartMap);
                break;
            case "ClassificationIsObject":
                assertClassificationIsObjectMessagePart(messagePartMap);
                break;
            case "MinimalTestCaseError":
            case "NullTestCaseError":
            case "EmptyTestCaseError":
                // Only difference is data null/empty/present
                // tested cases added to confirm no crash
                assertMinimalTestErrorMessageParts(messagePartMap);
                break;
        }
    }

    private void assertClassificationIsStringMessageParts(Map<String, String> messagePartMap) {
        assertEquals(3, messagePartMap.size());
        assertTrue(messagePartMap.containsKey("message"));
        assertNotNull(messagePartMap.get("message"));

        assertTrue(messagePartMap.containsKey("errorCode"));
        assertNotNull(messagePartMap.get("errorCode"));

        assertTrue(messagePartMap.containsKey("classification"));
        assertNotNull(messagePartMap.get("classification"));
    }

    private void assertClassificationIsObjectMessagePart(Map<String, String> messagePartMap) {
        assertEquals(4, messagePartMap.size());
        assertTrue(messagePartMap.containsKey("message"));
        assertNotNull(messagePartMap.get("message"));

        assertTrue(messagePartMap.containsKey("path"));
        assertNotNull(messagePartMap.get("path"));

        assertTrue(messagePartMap.containsKey("locations"));
        assertNotNull(messagePartMap.get("locations"));

        assertTrue(messagePartMap.containsKey("classification"));
        assertNotNull(messagePartMap.get("classification"));
    }

    private void assertMinimalTestErrorMessageParts(Map<String, String> messagePartMap) {
        assertEquals(2, messagePartMap.size());
        assertTrue(messagePartMap.containsKey("message"));
        assertNotNull(messagePartMap.get("message"));

        assertTrue(messagePartMap.containsKey("classification"));
        assertNotNull(messagePartMap.get("classification"));
    }

    private void mockDvadAPIHeaderValues() {
        when(mockPassportConfigurationService.getEncryptedSsmParameter(HMPO_API_HEADER_API_KEY))
                .thenReturn("TEST_KEY");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_USER_AGENT))
                .thenReturn("TEST_USER_AGENT");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_NETWORK_TYPE))
                .thenReturn("TEST_NETWORK_TYPE");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_CLIENT_ID))
                .thenReturn("TEST_CLIENT_ID");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_SECRET))
                .thenReturn("TEST_SECRET");
        when(mockPassportConfigurationService.getParameterValue(HMPO_API_HEADER_GRANT_TYPE))
                .thenReturn("TEST_GRANT_TYPE");
    }
}
