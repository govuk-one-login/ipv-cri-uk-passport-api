package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints;

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
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.AccessTokenResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.DvadAPIHeaderValues;
import uk.gov.di.ipv.cri.passport.checkpassport.util.HTTPReply;
import uk.gov.di.ipv.cri.passport.checkpassport.util.HTTPReplyHelper;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;

import java.io.IOException;
import java.net.URI;

import static uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.RequestHeaderKeys.HEADER_CONTENT_TYPE;
import static uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.RequestHeaderKeys.HEADER_REQ_ID;
import static uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.RequestHeaderKeys.HEADER_USER_AGENT;
import static uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.RequestHeaderKeys.HEADER_X_API_KEY;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_REQUEST_CREATED;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_REQUEST_SEND_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_REQUEST_SEND_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_EXPECTED_HTTP_STATUS;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_INVALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS;

public class TokenRequestService {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String ENDPOINT_NAME = "token endpoint";

    private final URI requestURI;

    private final CloseableHttpClient closeableHttpClient;
    private final RequestConfig requestConfig;

    private final ObjectMapper objectMapper;

    private final EventProbe eventProbe;

    public TokenRequestService(
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

    public AccessTokenResponse requestAccessToken(
            String requestId, DvadAPIHeaderValues dvadAPIHeaderValues)
            throws OAuthErrorResponseException {

        // Token Request is posted as if via a form
        final HttpPost request = new HttpPost();
        request.setURI(requestURI);
        request.addHeader(
                HEADER_CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.getMimeType());
        request.addHeader(HEADER_REQ_ID, requestId);
        request.addHeader(HEADER_X_API_KEY, dvadAPIHeaderValues.apiKey);
        request.addHeader(HEADER_USER_AGENT, dvadAPIHeaderValues.userAgent);

        // Enforce connection timeout values
        request.setConfig(requestConfig);

        // Body Params
        final String clientId = dvadAPIHeaderValues.clientId;
        final String secret = dvadAPIHeaderValues.secret;
        final String grantType = dvadAPIHeaderValues.grantType;
        final String audience = dvadAPIHeaderValues.audience;

        String requestBody =
                "clientId="
                        + clientId
                        + "&"
                        + "grantType="
                        + grantType
                        + "&"
                        + "secret="
                        + secret
                        + "&"
                        + "audience="
                        + audience;

        LOGGER.debug("Token request body : {}", requestBody);

        request.setEntity(new StringEntity(requestBody, ContentType.APPLICATION_FORM_URLENCODED));

        eventProbe.counterMetric(DVAD_TOKEN_REQUEST_CREATED.withEndpointPrefix());

        final HTTPReply httpReply;
        String requestURIString = requestURI.toString();
        LOGGER.debug("Token request endpoint is {}", requestURIString);
        LOGGER.info("Submitting token request to third party...");
        try (CloseableHttpResponse response = closeableHttpClient.execute(request)) {

            eventProbe.counterMetric(DVAD_TOKEN_REQUEST_SEND_OK.withEndpointPrefix());

            // throws OAuthErrorResponseException on error
            httpReply =
                    HTTPReplyHelper.retrieveStatusCodeAndBodyFromResponse(response, ENDPOINT_NAME);
        } catch (IOException e) {

            LOGGER.error("IOException executing token request - {}", e.getMessage());

            eventProbe.counterMetric(
                    DVAD_TOKEN_REQUEST_SEND_ERROR.withEndpointPrefixAndExceptionName(e));

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.ERROR_INVOKING_THIRD_PARTY_API_TOKEN_ENDPOINT);
        }

        if (httpReply.statusCode == 200) {
            LOGGER.info("Token status code {}", httpReply.statusCode);

            eventProbe.counterMetric(
                    DVAD_TOKEN_RESPONSE_TYPE_EXPECTED_HTTP_STATUS.withEndpointPrefix());

            try {
                LOGGER.debug("Token ResponseBody - {}", httpReply.responseBody);

                // DVAD_TOKEN_RESPONSE_TYPE_VALID not captured here as the token contents is
                // validated later

                return objectMapper.readValue(httpReply.responseBody, AccessTokenResponse.class);
            } catch (JsonProcessingException e) {
                LOGGER.error("JsonProcessingException mapping Token response");
                LOGGER.debug(e.getMessage());

                eventProbe.counterMetric(DVAD_TOKEN_RESPONSE_TYPE_INVALID.withEndpointPrefix());

                throw new OAuthErrorResponseException(
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_MAP_TOKEN_ENDPOINT_RESPONSE_BODY);
            }
        } else {
            // The token request responded but with an unexpected status code
            LOGGER.error("Token response status code was - {}", httpReply.statusCode);

            eventProbe.counterMetric(
                    DVAD_TOKEN_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS.withEndpointPrefix());

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.ERROR_TOKEN_ENDPOINT_RETURNED_UNEXPECTED_HTTP_STATUS_CODE);
        }
    }
}
