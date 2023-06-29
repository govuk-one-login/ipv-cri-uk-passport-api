package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.HealthCheckResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.DvadAPIHeaderValues;
import uk.gov.di.ipv.cri.passport.checkpassport.util.HTTPReply;
import uk.gov.di.ipv.cri.passport.checkpassport.util.HTTPReplyHelper;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;

import java.io.IOException;
import java.net.URI;

import static uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.RequestHeaderKeys.HEADER_REQ_ID;
import static uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.RequestHeaderKeys.HEADER_USER_AGENT;
import static uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.RequestHeaderKeys.HEADER_X_API_KEY;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_REQUEST_CREATED;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_REQUEST_SEND_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_REQUEST_SEND_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_RESPONSE_STATUS_DOWN;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_RESPONSE_STATUS_UP;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_RESPONSE_TYPE_EXPECTED_HTTP_STATUS;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_RESPONSE_TYPE_INVALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_HEALTH_RESPONSE_TYPE_VALID;

public class HealthCheckService {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String ENDPOINT_NAME = "health endpoint";

    private final URI requestURI;

    private final CloseableHttpClient closeableHttpClient;
    private final RequestConfig requestConfig;

    private final ObjectMapper objectMapper;

    private final EventProbe eventProbe;

    public HealthCheckService(
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
    }

    public boolean checkRemoteApiIsUp(String requestId, DvadAPIHeaderValues dvadAPIHeaderValues)
            throws OAuthErrorResponseException {

        HttpGet request = new HttpGet();
        request.setURI(requestURI);
        request.addHeader(HEADER_REQ_ID, requestId);
        request.addHeader(HEADER_X_API_KEY, dvadAPIHeaderValues.apiKey);
        request.addHeader(HEADER_USER_AGENT, dvadAPIHeaderValues.userAgent);

        // Enforce connection timeout values
        request.setConfig(requestConfig);

        eventProbe.counterMetric(DVAD_HEALTH_REQUEST_CREATED.withEndpointPrefix());

        final HTTPReply httpReply;
        String requestURIString = requestURI.toString();
        LOGGER.debug("Health check endpoint is {}", requestURIString);
        LOGGER.info("Submitting health check request to third party...");
        try (CloseableHttpResponse response = closeableHttpClient.execute(request)) {

            eventProbe.counterMetric(DVAD_HEALTH_REQUEST_SEND_OK.withEndpointPrefix());

            // Throws OAuthErrorResponseException on error
            httpReply =
                    HTTPReplyHelper.retrieveStatusCodeAndBodyFromResponse(response, ENDPOINT_NAME);
        } catch (IOException e) {
            LOGGER.error("IOException executing health check request - {}", e.getMessage());

            eventProbe.counterMetric(
                    DVAD_HEALTH_REQUEST_SEND_ERROR.withEndpointPrefixAndExceptionName(e));

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.ERROR_INVOKING_THIRD_PARTY_API_HEALTH_ENDPOINT);
        }

        if (httpReply.statusCode == 200) {
            LOGGER.info("HealthCheck status code {}", httpReply.statusCode);

            eventProbe.counterMetric(
                    DVAD_HEALTH_RESPONSE_TYPE_EXPECTED_HTTP_STATUS.withEndpointPrefix());

            try {
                LOGGER.debug("HealthCheck ResponseBody - {}", httpReply.responseBody);

                HealthCheckResponse healthCheckResponse =
                        objectMapper.readValue(httpReply.responseBody, HealthCheckResponse.class);

                String apiStatus = healthCheckResponse.getStatus();

                boolean remoteAPIsUP = apiStatus.equals("UP");

                String message =
                        String.format(
                                "API health check returned httpStatusCode %s with health status : %s",
                                httpReply.statusCode, apiStatus);
                LOGGER.info(message);

                // Endpoint reply json is valid...
                eventProbe.counterMetric(DVAD_HEALTH_RESPONSE_TYPE_VALID.withEndpointPrefix());

                // Metrics is captured here as http status errors are also returned as api down
                if (remoteAPIsUP) {
                    eventProbe.counterMetric(DVAD_HEALTH_RESPONSE_STATUS_UP.withEndpointPrefix());
                } else {
                    eventProbe.counterMetric(DVAD_HEALTH_RESPONSE_STATUS_DOWN.withEndpointPrefix());
                }

                return remoteAPIsUP;
            } catch (JsonProcessingException e) {
                LOGGER.error("JsonProcessingException mapping health check response");
                LOGGER.debug("JsonProcessingException - {}", e.getMessage());

                eventProbe.counterMetric(DVAD_HEALTH_RESPONSE_TYPE_INVALID.withEndpointPrefix());

                // Serious error as the API has replied but with something unexpected
                throw new OAuthErrorResponseException(
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_MAP_HEALTH_ENDPOINT_RESPONSE_BODY);
            }
        } else {
            // The health check responded but with an expected status code
            LOGGER.error("HealthCheck status code was : {}", httpReply.statusCode);

            eventProbe.counterMetric(
                    DVAD_HEALTH_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS.withEndpointPrefix());

            // This will be handled as if DOWN was returned
            return false;
        }
    }
}
