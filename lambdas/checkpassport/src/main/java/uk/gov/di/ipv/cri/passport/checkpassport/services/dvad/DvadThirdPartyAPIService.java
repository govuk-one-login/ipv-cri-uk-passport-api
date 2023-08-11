package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.AccessTokenResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.GraphQLAPIResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.errors.Errors;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.errors.Extensions;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.errors.Locations;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.ThirdPartyAPIResult;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.dvad.endpoints.GraphQLServiceResult;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.fields.APIResultSource;
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

import static uk.gov.di.ipv.cri.passport.checkpassport.domain.result.fields.APIResultSource.DVAD;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_GRAPHQL_QUERY_STRING;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_INVALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_VALID;

public class DvadThirdPartyAPIService implements ThirdPartyAPIService {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final APIResultSource API_RESULT_SOURCE = DVAD;

    private static final String SERVICE_NAME = DvadThirdPartyAPIService.class.getSimpleName();

    private final EventProbe eventProbe;

    private final PassportConfigurationService passportConfigurationService;

    private static final String VALIDATION_RESULT_FIELD = "validationResult";

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

        LOGGER.info(() -> String.format("%s reading header parameters", SERVICE_NAME));
        final DvadAPIHeaderValues dvadAPIHeaderValues =
                new DvadAPIHeaderValues(passportConfigurationService);
        LOGGER.info(() -> String.format("%s header parameters set", SERVICE_NAME));

        // Perform API Health Check
        final boolean remoteAPIsUP = healthCheckService.checkRemoteApiIsUp(dvadAPIHeaderValues);

        if (!remoteAPIsUP) {
            LOGGER.error("Remote API is down");
            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.ERROR_THIRD_PARTY_API_HEALTH_ENDPOINT_NOT_UP);
        }
        LOGGER.info("Remote API is UP");

        AccessTokenResponse accessTokenResponse =
                tokenRequestService.requestAccessToken(dvadAPIHeaderValues, true);

        // Retrieved per connection to allow query change with-out re-deploy (power-tools cached)
        final String queryString =
                passportConfigurationService.getEncryptedSsmParameter(HMPO_GRAPHQL_QUERY_STRING);

        GraphQLServiceResult graphQLServiceResult =
                graphQLRequestService.performGraphQLQuery(
                        accessTokenResponse, dvadAPIHeaderValues, queryString, passportFormData);

        GraphQLAPIResponse graphQLAPIResponse = graphQLServiceResult.getGraphQLAPIResponse();
        String graphQLRequestId = graphQLServiceResult.getRequestId();

        // Fatal - if errors found - Throws OAuthErrorResponseException
        assertNoErrorsSetInGraphQLResponse(graphQLAPIResponse);

        // Checks the response has the required fields for mapping
        GraphQLAPIResponseValidationResult graphQLAPIResponseValidationResult =
                validateAPISuccessResponse(graphQLAPIResponse);

        if (!graphQLAPIResponseValidationResult.valid) {

            // We got an API response, but it's not valid for the CRI to process
            LOGGER.error(
                    "API Response Failed validation - {}",
                    graphQLAPIResponseValidationResult.failureReason);

            eventProbe.counterMetric(DVAD_GRAPHQL_RESPONSE_TYPE_INVALID.withEndpointPrefix());

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.DVAD_API_RESPONSE_NOT_VALID);
        }

        // If there is failure after this point then validation needs updated
        eventProbe.counterMetric(DVAD_GRAPHQL_RESPONSE_TYPE_VALID.withEndpointPrefix());

        ThirdPartyAPIResult result = mapAPIResponseToAPIResult(graphQLAPIResponse);

        // Record the requestId used for the successful transaction
        result.setTransactionId(graphQLRequestId);

        result.setApiResultSource(API_RESULT_SOURCE);

        return result;
    }

    private void assertNoErrorsSetInGraphQLResponse(GraphQLAPIResponse graphQLAPIResponse)
            throws OAuthErrorResponseException {
        final List<Errors> errors = graphQLAPIResponse.getErrors();
        boolean errorResponse = (errors != null);

        // Errors only exists if the remote API did not accept the request
        if (errorResponse) {

            List<String> errorMessage = new ArrayList<>();

            for (Errors error : errors) {
                errorMessage.add(getErrorLine(error));
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

    private String getErrorLine(Errors error) {

        // There are multiple Error response formats with optional fields and overloaded types

        String messageSegment = String.format("message %s, ", error.getMessage());

        List<String> path = error.getPath();
        String pathSegment = path == null || path.isEmpty() ? "" : String.format("path %s,", path);

        List<Locations> locations = error.getLocations();
        String locationsSegment =
                locations == null || locations.isEmpty()
                        ? ""
                        : String.format("locations %s, ", locations);

        Extensions extensions = error.getExtensions();

        String errorCode = extensions.getErrorCode();
        String errorCodeSegment =
                errorCode == null ? "" : String.format("errorCode %s, ", errorCode);

        // Classification displayed last as its value may single string or a complex object (as a
        // string)
        String classification = extensions.getClassification().toString();
        String classificationSegment = String.format("classification %s", classification);

        // Spaces added in segments to avoid adding space when segment not present
        return String.format(
                "Error : %s%s%s%s%s",
                messageSegment,
                pathSegment,
                locationsSegment,
                errorCodeSegment,
                classificationSegment);
    }

    private GraphQLAPIResponseValidationResult validateAPISuccessResponse(
            GraphQLAPIResponse graphQLAPIResponse) {

        if (graphQLAPIResponse.getData() == null) {

            return GraphQLAPIResponseValidationResult.builder()
                    .valid(false)
                    .failureReason("API Response Data is null")
                    .build();
        }

        if (graphQLAPIResponse.getData().getValidatePassport() == null) {

            return GraphQLAPIResponseValidationResult.builder()
                    .valid(false)
                    .failureReason("API Response ValidatePassport is null")
                    .build();
        }

        if (graphQLAPIResponse.getData().getValidatePassport().size() == 0) {

            return GraphQLAPIResponseValidationResult.builder()
                    .valid(false)
                    .failureReason("API Response ValidatePassport is empty")
                    .build();
        }

        if (!graphQLAPIResponse
                .getData()
                .getValidatePassport()
                .containsKey(VALIDATION_RESULT_FIELD)) {

            return GraphQLAPIResponseValidationResult.builder()
                    .valid(false)
                    .failureReason(
                            String.format(
                                    "API Response ValidatePassport is missing %s",
                                    VALIDATION_RESULT_FIELD))
                    .build();
        }

        return GraphQLAPIResponseValidationResult.builder().valid(true).build();
    }

    private ThirdPartyAPIResult mapAPIResponseToAPIResult(GraphQLAPIResponse graphQLAPIResponse) {

        ThirdPartyAPIResult result = new ThirdPartyAPIResult();

        Map<String, String> validatePassportMap =
                graphQLAPIResponse.getData().getValidatePassport();

        // Remove the main validation field from the map
        String validationResultValue = validatePassportMap.remove(VALIDATION_RESULT_FIELD);

        boolean isValid = Boolean.parseBoolean(validationResultValue);

        String message = String.format("isValid %s", isValid);
        LOGGER.info(message);

        result.setValid(isValid);

        // Remaining fields are treated as response flags
        result.setFlags(validatePassportMap);

        return result;
    }
}
