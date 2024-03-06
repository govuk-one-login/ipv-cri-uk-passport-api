package uk.gov.di.ipv.cri.passport.library.dvad.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.PassportFormTestDataGenerator;
import uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.domain.result.ThirdPartyAPIResult;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.AccessTokenResponse;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.GraphQLAPIResponse;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields.ResponseData;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields.errors.Errors;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.result.endpoints.GraphQLServiceResult;
import uk.gov.di.ipv.cri.passport.library.dvad.services.endpoints.DvadAPIEndpointFactory;
import uk.gov.di.ipv.cri.passport.library.dvad.services.endpoints.GraphQLRequestService;
import uk.gov.di.ipv.cri.passport.library.dvad.services.endpoints.HealthCheckService;
import uk.gov.di.ipv.cri.passport.library.dvad.services.endpoints.TokenRequestService;
import uk.gov.di.ipv.cri.passport.library.dvad.util.responses.GraphQLAPIErrorDataGenerator;
import uk.gov.di.ipv.cri.passport.library.dvad.util.responses.ResponseDataGenerator;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;
import uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;
import uk.gov.di.ipv.cri.passport.library.service.ThirdPartyAPIService;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DvadThirdPartyAPIServiceTest {

    private ObjectMapper realObjectMapper;

    @Mock private EventProbe mockEventProbe;

    @Mock private CloseableHttpClient mockCloseableHttpClient;

    @Mock private ParameterStoreService mockParameterStoreService;

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
                        mockParameterStoreService,
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
        when(mockParameterStoreService.getEncryptedParameterValue(
                        ParameterStoreParameters.HMPO_GRAPHQL_QUERY_STRING))
                .thenReturn(TEST_QUERY_STRING);

        when(mockGraphQLRequestService.performGraphQLQuery(
                        eq(testValidAccessTokenResponse),
                        any(DvadAPIHeaderValues.class),
                        eq(TEST_QUERY_STRING),
                        eq(passportFormData)))
                .thenReturn(testGraphQLServiceResult);

        ThirdPartyAPIResult result = dvadThirdPartyAPIServiceTest.performCheck(passportFormData);

        // Using the correct third party API?
        Assertions.assertEquals(
                dvadThirdPartyAPIServiceTest.getServiceName(),
                DvadThirdPartyAPIService.class.getSimpleName());

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe)
                .counterMetric(
                        ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_VALID
                                .withEndpointPrefix());
        verifyNoMoreInteractions(mockEventProbe);

        assertNotNull(result);
        assertNotNull(result.getTransactionId());
        assertNotNull(result.getFlags());

        Assertions.assertEquals(expectedIsValid, result.isValid());
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
        when(mockParameterStoreService.getEncryptedParameterValue(
                        ParameterStoreParameters.HMPO_GRAPHQL_QUERY_STRING))
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
                Assertions.assertThrows(
                        OAuthErrorResponseException.class,
                        () -> dvadThirdPartyAPIServiceTest.performCheck(passportFormData),
                        "Expected OAuthErrorResponseException");

        Assertions.assertEquals(
                dvadThirdPartyAPIServiceTest.getServiceName(),
                DvadThirdPartyAPIService.class.getSimpleName());

        InOrder inOrder = inOrder(mockEventProbe);
        if (errors) {
            inOrder.verify(mockEventProbe)
                    .counterMetric(
                            ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_ERROR
                                    .withEndpointPrefix());
        } else {
            inOrder.verify(mockEventProbe)
                    .counterMetric(
                            ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_INVALID
                                    .withEndpointPrefix());
        }
        verifyNoMoreInteractions(mockEventProbe);

        Assertions.assertEquals(
                expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        Assertions.assertEquals(
                expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
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
                Assertions.assertThrows(
                        OAuthErrorResponseException.class,
                        () -> dvadThirdPartyAPIServiceTest.performCheck(passportFormData),
                        "Expected OAuthErrorResponseException");

        Assertions.assertEquals(
                expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        Assertions.assertEquals(
                expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
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

        when(mockParameterStoreService.getEncryptedParameterValue(
                        ParameterStoreParameters.HMPO_GRAPHQL_QUERY_STRING))
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
                Assertions.assertThrows(
                        OAuthErrorResponseException.class,
                        () -> dvadThirdPartyAPIServiceTest.performCheck(passportFormData),
                        "Expected OAuthErrorResponseException");

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe)
                .counterMetric(
                        ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_INVALID
                                .withEndpointPrefix());
        verifyNoMoreInteractions(mockEventProbe);

        Assertions.assertEquals(
                expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        Assertions.assertEquals(
                expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
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
                        mockParameterStoreService,
                        mockEventProbe,
                        mockCloseableHttpClient,
                        realObjectMapper);

        spyDvadThirdPartyAPIService = Mockito.spy(spyTarget);

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
        // Mock Parameter store fetches in DvadAPIHeaderValues
        Map<String, String> testParameterMap =
                Map.of(
                        DvadAPIHeaderValues.MAP_KEY_APIKEY,
                        "TEST_KEY",
                        DvadAPIHeaderValues.MAP_KEY_USERAGENT,
                        "TEST_USER_AGENT",
                        DvadAPIHeaderValues.MAP_KEY_NETWORKTYPE,
                        "TEST_NETWORK_TYPE",
                        DvadAPIHeaderValues.MAP_KEY_CLIENTID,
                        "TEST_CLIENT_ID",
                        DvadAPIHeaderValues.MAP_KEY_SECRET,
                        "TEST_SECRET",
                        DvadAPIHeaderValues.MAP_KEY_GRANTTYPE,
                        "TEST_GRANT_TYPE");

        when(mockParameterStoreService.getAllParametersFromPathWithDecryption(
                        ParameterStoreParameters.HMPO_API_HEADER_PARAMETER_PATH))
                .thenReturn(testParameterMap);
    }
}
