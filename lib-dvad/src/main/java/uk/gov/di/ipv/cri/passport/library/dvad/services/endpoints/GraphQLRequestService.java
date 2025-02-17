package uk.gov.di.ipv.cri.passport.library.dvad.services.endpoints;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.request.GraphQLRequest;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.request.Input;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.request.Variables;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.AccessTokenResponse;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.GraphQLAPIResponse;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.result.endpoints.GraphQLServiceResult;
import uk.gov.di.ipv.cri.passport.library.dvad.services.DvadAPIHeaderValues;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;
import uk.gov.di.ipv.cri.passport.library.util.HTTPReply;
import uk.gov.di.ipv.cri.passport.library.util.HTTPReplyHelper;
import uk.gov.di.ipv.cri.passport.library.util.StopWatch;

import java.io.IOException;
import java.net.URI;
import java.util.UUID;

import static uk.gov.di.ipv.cri.passport.library.dvad.domain.response.RequestHeaderKeys.HEADER_AUTHORIZATION;
import static uk.gov.di.ipv.cri.passport.library.dvad.domain.response.RequestHeaderKeys.HEADER_CONTENT_TYPE;
import static uk.gov.di.ipv.cri.passport.library.dvad.domain.response.RequestHeaderKeys.HEADER_DVAD_NETWORK_TYPE;
import static uk.gov.di.ipv.cri.passport.library.dvad.domain.response.RequestHeaderKeys.HEADER_REQ_ID;
import static uk.gov.di.ipv.cri.passport.library.dvad.domain.response.RequestHeaderKeys.HEADER_USER_AGENT;
import static uk.gov.di.ipv.cri.passport.library.dvad.domain.response.RequestHeaderKeys.HEADER_X_API_KEY;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_REQUEST_CREATED;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_REQUEST_SEND_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_REQUEST_SEND_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_LATENCY;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_EXPECTED_HTTP_STATUS;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_INVALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_GRAPHQL_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS;

public class GraphQLRequestService {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String ENDPOINT_NAME = "graphql endpoint";

    private final URI requestURI;

    private final CloseableHttpClient closeableHttpClient;
    private final RequestConfig requestConfig;

    private final ObjectMapper objectMapper;

    private final EventProbe eventProbe;

    private final StopWatch stopWatch;

    public GraphQLRequestService(
            String endpoint,
            CloseableHttpClient closeableHttpClient,
            RequestConfig requestConfig,
            ObjectMapper objectMapper,
            EventProbe eventProbe) {
        this.requestURI = URI.create(endpoint);
        this.closeableHttpClient = closeableHttpClient;
        this.requestConfig = requestConfig;
        this.objectMapper = objectMapper;
        this.eventProbe = eventProbe;
        this.stopWatch = new StopWatch();
    }

    public GraphQLServiceResult performGraphQLQuery(
            AccessTokenResponse accessTokenResponse,
            DvadAPIHeaderValues dvadAPIHeaderValues,
            String queryString,
            PassportFormData passportFormData)
            throws OAuthErrorResponseException {

        final String requestId = UUID.randomUUID().toString();
        LOGGER.info("{} Request Id {}", ENDPOINT_NAME, requestId);

        final String accessTokenValue = accessTokenResponse.accessToken();
        final String tokenType = accessTokenResponse.tokenType();

        // GraphQL Request is posted as if JSON
        final HttpPost request = new HttpPost();
        request.setURI(requestURI);
        request.addHeader(HEADER_CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType());
        request.addHeader(HEADER_REQ_ID, requestId);
        request.addHeader(HEADER_X_API_KEY, dvadAPIHeaderValues.apiKey);
        request.addHeader(HEADER_USER_AGENT, dvadAPIHeaderValues.userAgent);
        request.addHeader(HEADER_DVAD_NETWORK_TYPE, dvadAPIHeaderValues.networkType);
        request.addHeader(
                HEADER_AUTHORIZATION, String.format("%s %s", tokenType, accessTokenValue));

        // Enforce connection timeout values
        request.setConfig(requestConfig);

        // Body Params
        String requestBody;
        try {
            Variables variables = new Variables(new Input(passportFormData));

            GraphQLRequest graphQLRequest =
                    GraphQLRequest.builder().query(queryString).variables(variables).build();

            requestBody = objectMapper.writeValueAsString(graphQLRequest);
        } catch (JsonProcessingException e) {
            // PII in variables
            LOGGER.error("JsonProcessingException creating request body");
            LOGGER.debug(e.getMessage());
            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PREPARE_GRAPHQL_REQUEST_PAYLOAD);
        }

        LOGGER.debug("GraphQL request body : {}", requestBody);

        request.setEntity(new StringEntity(requestBody, ContentType.APPLICATION_JSON));

        eventProbe.counterMetric(DVAD_GRAPHQL_REQUEST_CREATED.withEndpointPrefix());

        final HTTPReply httpReply;
        String requestURIString = requestURI.toString();
        LOGGER.debug("GraphQL request endpoint is {}", requestURIString);
        LOGGER.info("Submitting GraphQL request to third party...");
        stopWatch.start();
        try (CloseableHttpResponse response = closeableHttpClient.execute(request)) {

            eventProbe.counterMetric(DVAD_GRAPHQL_REQUEST_SEND_OK.withEndpointPrefix());

            // throws OAuthErrorResponseException on error
            httpReply =
                    HTTPReplyHelper.retrieveStatusCodeAndBodyFromResponse(response, ENDPOINT_NAME);
        } catch (IOException e) {
            // No Response Latency
            eventProbe.counterMetric(
                    DVAD_GRAPHQL_RESPONSE_LATENCY.withEndpointPrefix(), stopWatch.stop());

            LOGGER.error("IOException executing GraphQL request - {}", e.getMessage());

            eventProbe.counterMetric(
                    DVAD_GRAPHQL_REQUEST_SEND_ERROR.withEndpointPrefixAndExceptionName(e));

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.ERROR_INVOKING_THIRD_PARTY_API_GRAPHQL_ENDPOINT);
        }

        // Response Latency
        eventProbe.counterMetric(
                DVAD_GRAPHQL_RESPONSE_LATENCY.withEndpointPrefix(), stopWatch.stop());

        if (httpReply.statusCode == 200) {

            LOGGER.info("GraphQL status code {}", httpReply.statusCode);

            eventProbe.counterMetric(
                    DVAD_GRAPHQL_RESPONSE_TYPE_EXPECTED_HTTP_STATUS.withEndpointPrefix());

            LOGGER.debug("performGraphQLQuery response {}", httpReply.responseBody);

            try {
                GraphQLAPIResponse graphQLAPIResponse =
                        objectMapper.readValue(httpReply.responseBody, GraphQLAPIResponse.class);

                return GraphQLServiceResult.builder()
                        .graphQLAPIResponse(graphQLAPIResponse)
                        .requestId(requestId)
                        .build();
            } catch (JsonProcessingException e) {

                LOGGER.error("JsonProcessingException mapping GraphQL response");
                LOGGER.debug(e.getMessage());

                // Invalid due to json mapping fail
                eventProbe.counterMetric(DVAD_GRAPHQL_RESPONSE_TYPE_INVALID.withEndpointPrefix());

                throw new OAuthErrorResponseException(
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_MAP_GRAPHQL_ENDPOINT_RESPONSE_BODY);
            }
        } else {
            // GraphQL endpoint responded but with an unexpected status code
            LOGGER.error(
                    "GraphQL response status code {} content - {}",
                    httpReply.statusCode,
                    httpReply.responseBody);

            eventProbe.counterMetric(
                    DVAD_GRAPHQL_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS.withEndpointPrefix());

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.ERROR_GRAPHQL_ENDPOINT_RETURNED_UNEXPECTED_HTTP_STATUS_CODE);
        }
    }
}
