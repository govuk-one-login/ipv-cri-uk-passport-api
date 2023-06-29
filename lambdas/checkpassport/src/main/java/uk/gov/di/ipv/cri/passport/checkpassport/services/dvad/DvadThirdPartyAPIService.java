package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.APIResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.AccessTokenResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.Errors;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.ValidationResult;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.ThirdPartyAPIResult;
import uk.gov.di.ipv.cri.passport.checkpassport.services.ThirdPartyAPIService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints.DvadAPIEndpointFactory;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints.GraphQLRequestService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints.HealthCheckService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints.TokenRequestService;
import uk.gov.di.ipv.cri.passport.library.config.HttpRequestConfig;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_GRAPHQL_QUERY_STRING;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_INVALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_VALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_INVALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_VALID;

public class DvadThirdPartyAPIService implements ThirdPartyAPIService {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String SERVICE_NAME = DvadThirdPartyAPIService.class.getSimpleName();

    private final EventProbe eventProbe;

    private final PassportConfigurationService passportConfigurationService;

    private static final long MAX_ALLOWED_ACCESS_TOKEN_LIFETIME = 1800L;
    private static final String BEARER_TOKEN_TYPE = "Bearer";

    private final ObjectMapper objectMapper;

    private final HealthCheckService healthCheckService;
    private final TokenRequestService tokenRequestService;
    private final GraphQLRequestService graphQLRequestService;

    public DvadThirdPartyAPIService(
            DvadAPIEndpointFactory dvadAPIEndpointFactory,
            PassportConfigurationService passportConfigurationService,
            EventProbe eventProbe,
            CloseableHttpClient closeableHttpClient,
            ObjectMapper objectMapper) {

        this.passportConfigurationService = passportConfigurationService;
        this.eventProbe = eventProbe;
        this.objectMapper = objectMapper;

        // Same on all endpoints
        final RequestConfig defaultRequestConfig =
                new HttpRequestConfig().getDefaultRequestConfig();

        // To reduce constructor load and allow services to be mocked
        healthCheckService =
                dvadAPIEndpointFactory.createHealthCheckService(
                        closeableHttpClient, defaultRequestConfig, objectMapper, eventProbe);
        tokenRequestService =
                dvadAPIEndpointFactory.createTokenRequestService(
                        closeableHttpClient, defaultRequestConfig, objectMapper, eventProbe);
        graphQLRequestService =
                dvadAPIEndpointFactory.createGraphQLRequestService(
                        closeableHttpClient, defaultRequestConfig, objectMapper, eventProbe);
    }

    @Override
    public String getServiceName() {
        return SERVICE_NAME;
    }

    @Override
    public ThirdPartyAPIResult performCheck(PassportFormData passportFormData)
            throws OAuthErrorResponseException {

        // For DVAD txn is generated CRI side
        final String requestId = UUID.randomUUID().toString();

        // "API" Added to aid filtering log messages for this value
        LOGGER.info("API Request Id {}", requestId);

        LOGGER.info(() -> String.format("%s reading header parameters", SERVICE_NAME));
        final DvadAPIHeaderValues dvadAPIHeaderValues =
                new DvadAPIHeaderValues(passportConfigurationService);
        LOGGER.info(() -> String.format("%s header parameters set", SERVICE_NAME));

        // Perform API Health Check
        final boolean remoteAPIsUP =
                healthCheckService.checkRemoteApiIsUp(requestId, dvadAPIHeaderValues);

        if (!remoteAPIsUP) {
            LOGGER.error("Remote API is down");
            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.ERROR_THIRD_PARTY_API_HEALTH_ENDPOINT_NOT_UP);
        }
        LOGGER.info("Remote API is UP");

        // Request an Access Token
        final AccessTokenResponse accessTokenResponse =
                tokenRequestService.requestAccessToken(requestId, dvadAPIHeaderValues);

        // Fatal if any problems throws OAuthErrorResponseException
        assertAccessTokenResponseIsValid(accessTokenResponse);

        // Retrieved per connection to allow query change with-out re-deploy (power-tools cached)
        final String queryString =
                passportConfigurationService.getEncryptedSsmParameter(HMPO_GRAPHQL_QUERY_STRING);

        // Send GraphQL Request
        String apiResponseAsString =
                graphQLRequestService.performGraphQLQuery(
                        requestId,
                        accessTokenResponse,
                        dvadAPIHeaderValues,
                        queryString,
                        passportFormData);
        LOGGER.debug("performGraphQLQuery response {}", apiResponseAsString);

        // Map Response - all errors are thrown as OAuthErrorResponseException
        ThirdPartyAPIResult result = processGraphQLResponse(apiResponseAsString);

        // Record the requestId used for the successful transaction
        result.setTransactionId(requestId);

        return result;
    }

    private void assertAccessTokenResponseIsValid(AccessTokenResponse accessTokenResponse)
            throws OAuthErrorResponseException {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                    String.format(
                            "BearerAccessToken is (T/V)  : %s %s %s",
                            accessTokenResponse.getTokenType(),
                            accessTokenResponse.getAccessToken(),
                            accessTokenResponse.getExpiresIn()));
        }

        String tokenType = accessTokenResponse.getTokenType();
        long tokenLifetime = accessTokenResponse.getExpiresIn();

        if (!tokenType.equals(BEARER_TOKEN_TYPE)) {
            LOGGER.error(
                    "Access Token TokenType {} is not of type {}", tokenType, BEARER_TOKEN_TYPE);

            eventProbe.counterMetric(DVAD_TOKEN_RESPONSE_TYPE_INVALID.withEndpointPrefix());

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_VERIFY_ACCESS_TOKEN);
        }

        if (tokenLifetime <= 0 || tokenLifetime > MAX_ALLOWED_ACCESS_TOKEN_LIFETIME) {
            LOGGER.error(
                    "Access Token Lifetime is invalid - value {}, min 1, max {}",
                    tokenLifetime,
                    MAX_ALLOWED_ACCESS_TOKEN_LIFETIME);

            eventProbe.counterMetric(DVAD_TOKEN_RESPONSE_TYPE_INVALID.withEndpointPrefix());

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_VERIFY_ACCESS_TOKEN);
        }

        // No exceptions Token response is seen as valid
        eventProbe.counterMetric(DVAD_TOKEN_RESPONSE_TYPE_VALID.withEndpointPrefix());
    }

    private ThirdPartyAPIResult processGraphQLResponse(String apiResponseAsString)
            throws OAuthErrorResponseException {

        APIResponse apiResponse;
        try {
            apiResponse = objectMapper.readValue(apiResponseAsString, APIResponse.class);
        } catch (JsonProcessingException e) {

            LOGGER.error("JsonProcessingException mapping GraphQL response");
            LOGGER.debug(e.getMessage());

            // Invalid due to json mapping fail
            eventProbe.counterMetric(DVAD_GRAPHQL_RESPONSE_TYPE_INVALID.withEndpointPrefix());

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_MAP_GRAPHQL_ENDPOINT_RESPONSE_BODY);
        }

        // Fatal - if errors found - Throws OAuthErrorResponseException
        assertNoErrorsSetInGraphQLResponse(apiResponse);

        // Checks the response has the required fields for mapping
        APIResponseValidationResult apiResponseValidationResult =
                validateAPISuccessResponse(apiResponse);

        if (!apiResponseValidationResult.valid) {

            // We got an API response, but it's not valid for the CRI to process
            LOGGER.error(
                    "API Response Failed validation - {}",
                    apiResponseValidationResult.failureReason);

            eventProbe.counterMetric(DVAD_GRAPHQL_RESPONSE_TYPE_INVALID.withEndpointPrefix());

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.DVAD_API_RESPONSE_NOT_VALID);
        }

        // If there is failure after this point then validation needs updated
        eventProbe.counterMetric(DVAD_GRAPHQL_RESPONSE_TYPE_VALID.withEndpointPrefix());

        // Creates and Returns ThirdPartyAPIResult
        return mapAPIResponseToAPIResult(apiResponse);
    }

    private APIResponseValidationResult validateAPISuccessResponse(APIResponse apiResponse) {

        if (apiResponse.getData() == null) {

            return APIResponseValidationResult.builder()
                    .valid(false)
                    .failureReason("API Response Data is null")
                    .build();
        }

        if (apiResponse.getData().getValidatePassportData() == null) {

            return APIResponseValidationResult.builder()
                    .valid(false)
                    .failureReason("API Response ValidatePassportData is null")
                    .build();
        }

        if (apiResponse.getData().getValidatePassportData().getValidationResult() == null) {
            return APIResponseValidationResult.builder()
                    .valid(false)
                    .failureReason("API Response ValidationResult is null")
                    .build();
        }

        // Matches if null is mapped as an empty map via Jackson

        return APIResponseValidationResult.builder().valid(true).build();
    }

    private ThirdPartyAPIResult mapAPIResponseToAPIResult(APIResponse apiResponse) {

        ThirdPartyAPIResult result = new ThirdPartyAPIResult();

        boolean passportFound = apiResponse.getData().getValidatePassportData().isPassportFound();

        ValidationResult validationResult =
                apiResponse.getData().getValidatePassportData().getValidationResult();

        // Was both the passport "found" and all overall validationResult a success
        boolean isValid = passportFound && validationResult == ValidationResult.SUCCESS;

        String message =
                String.format(
                        "passportFound %s, validationResult %s - isValid %s",
                        passportFound, validationResult, isValid);
        LOGGER.info(message);

        Map<String, String> responseFlags =
                apiResponse.getData().getValidatePassportData().getMatches();

        result.setValid(isValid);
        result.setFlags(responseFlags);

        return result;
    }

    private void assertNoErrorsSetInGraphQLResponse(APIResponse apiResponse)
            throws OAuthErrorResponseException {
        final List<Errors> errors = apiResponse.getErrors();
        boolean errorResponse = (errors != null);

        // Errors only exists if the remote API did not accept the request
        if (errorResponse) {

            List<String> errorMessage = new ArrayList<>();

            for (Errors error : errors) {
                String errorLine =
                        String.format(
                                "Code: %s Message: %s",
                                error.getExtensions().getCode(), error.getMessage());
                errorMessage.add(errorLine);
            }

            String combinedErrors = String.join(", ", errorMessage.toString());
            LOGGER.error("API Responded with errors - {}", combinedErrors);

            eventProbe.counterMetric(
                    DVAD_GRAPHQL_RESPONSE_TYPE_ERROR
                            .withEndpointPrefix()); // A Specific Error from API

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.GRAPHQL_ENDPOINT_RETURNED_AN_ERROR_RESPONSE);
        }
    }
}
