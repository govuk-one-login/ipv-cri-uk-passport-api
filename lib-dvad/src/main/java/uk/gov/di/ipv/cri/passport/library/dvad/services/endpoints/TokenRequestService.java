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
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.AccessTokenResponse;
import uk.gov.di.ipv.cri.passport.library.dvad.services.AccessTokenResponseCache;
import uk.gov.di.ipv.cri.passport.library.dvad.services.DvadAPIHeaderValues;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;
import uk.gov.di.ipv.cri.passport.library.util.HTTPReply;
import uk.gov.di.ipv.cri.passport.library.util.HTTPReplyHelper;
import uk.gov.di.ipv.cri.passport.library.util.StopWatch;

import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.time.ZoneId;
import java.util.UUID;

import static uk.gov.di.ipv.cri.passport.library.dvad.domain.response.RequestHeaderKeys.HEADER_CONTENT_TYPE;
import static uk.gov.di.ipv.cri.passport.library.dvad.domain.response.RequestHeaderKeys.HEADER_DVAD_NETWORK_TYPE;
import static uk.gov.di.ipv.cri.passport.library.dvad.domain.response.RequestHeaderKeys.HEADER_REQ_ID;
import static uk.gov.di.ipv.cri.passport.library.dvad.domain.response.RequestHeaderKeys.HEADER_USER_AGENT;
import static uk.gov.di.ipv.cri.passport.library.dvad.domain.response.RequestHeaderKeys.HEADER_X_API_KEY;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_REQUEST_CREATED;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_REQUEST_REUSING_CACHED_TOKEN;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_REQUEST_SEND_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_REQUEST_SEND_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_LATENCY;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_EXPECTED_HTTP_STATUS;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_INVALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DVAD_TOKEN_RESPONSE_TYPE_VALID;

public class TokenRequestService {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String ENDPOINT_NAME = "token endpoint";

    public static final long MAX_ALLOWED_ACCESS_TOKEN_LIFETIME_SECONDS = 1800L;
    public static final long ACCESS_TOKEN_EXPIRATION_WINDOW_SECONDS = 30L;
    private static final String BEARER_TOKEN_TYPE = "Bearer";

    private final URI requestURI;

    private final CloseableHttpClient closeableHttpClient;
    private final RequestConfig requestConfig;

    private final ObjectMapper objectMapper;

    private final EventProbe eventProbe;

    private AccessTokenResponseCache accessTokenResponseCache = null;

    private final StopWatch stopWatch;

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
        this.stopWatch = new StopWatch();
    }

    public AccessTokenResponse requestAccessToken(
            DvadAPIHeaderValues dvadAPIHeaderValues, boolean alwaysRequestNewToken)
            throws OAuthErrorResponseException {

        boolean existingCachedToken = accessTokenResponseCache != null;
        boolean existingCachedTokenNearExpiry =
                existingCachedToken
                        && accessTokenResponseCache.isNearExpiration(
                                ACCESS_TOKEN_EXPIRATION_WINDOW_SECONDS);

        if (alwaysRequestNewToken) {
            LOGGER.info("AccessToken cache override enabled - always requesting a new token");
        }

        boolean newTokenRequest =
                alwaysRequestNewToken || (!existingCachedToken || existingCachedTokenNearExpiry);

        // Request an Access Token
        if (newTokenRequest) {

            if (existingCachedToken) {
                long oldExpiresTime = accessTokenResponseCache.getExpiresTime();

                LOGGER.info(
                        "Requesting new AccessToken - cached token is nearing or passed expiration time of {} UTC",
                        Instant.ofEpochMilli(oldExpiresTime)
                                .atZone(ZoneId.systemDefault())
                                .toLocalDateTime());
            } else {
                LOGGER.info("Requesting new AccessToken - no existing cached token");
            }

            AccessTokenResponse newAccessTokenResponse =
                    performNewTokenRequest(dvadAPIHeaderValues);

            // Fatal if any problems throws OAuthErrorResponseException
            assertAccessTokenResponseIsValid(newAccessTokenResponse);

            // Token response is valid and cached until near expiry
            accessTokenResponseCache =
                    new AccessTokenResponseCache(
                            newAccessTokenResponse, MAX_ALLOWED_ACCESS_TOKEN_LIFETIME_SECONDS);

            long newExpiresTime = accessTokenResponseCache.getExpiresTime();
            LOGGER.info(
                    "AccessToken cached - expires {} UTC",
                    Instant.ofEpochMilli(newExpiresTime)
                            .atZone(ZoneId.systemDefault())
                            .toLocalDateTime());
        } else {
            long expiresTime = accessTokenResponseCache.getExpiresTime();

            LOGGER.info(
                    "Re-using cached AccessToken - expires {} UTC",
                    Instant.ofEpochMilli(expiresTime)
                            .atZone(ZoneId.systemDefault())
                            .toLocalDateTime());

            eventProbe.counterMetric(DVAD_TOKEN_REQUEST_REUSING_CACHED_TOKEN.withEndpointPrefix());
        }

        return accessTokenResponseCache.cachedAccessTokenResponse();
    }

    private AccessTokenResponse performNewTokenRequest(DvadAPIHeaderValues dvadAPIHeaderValues)
            throws OAuthErrorResponseException {

        final String requestId = UUID.randomUUID().toString();
        LOGGER.info("{} Request Id {}", ENDPOINT_NAME, requestId);

        // Token Request is posted as if via a form
        final HttpPost request = new HttpPost();
        request.setURI(requestURI);
        request.addHeader(
                HEADER_CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.getMimeType());
        request.addHeader(HEADER_REQ_ID, requestId);
        request.addHeader(HEADER_X_API_KEY, dvadAPIHeaderValues.apiKey);
        request.addHeader(HEADER_USER_AGENT, dvadAPIHeaderValues.userAgent);
        request.addHeader(HEADER_DVAD_NETWORK_TYPE, dvadAPIHeaderValues.networkType);

        // Enforce connection timeout values
        request.setConfig(requestConfig);

        // Body Params
        final String clientId = dvadAPIHeaderValues.clientId;
        final String secret = dvadAPIHeaderValues.secret;
        final String grantType = dvadAPIHeaderValues.grantType;

        String requestBody =
                "clientId=" + clientId + "&secret=" + secret + "&grantType=" + grantType;

        LOGGER.debug("Token request body : {}", requestBody);

        request.setEntity(new StringEntity(requestBody, ContentType.APPLICATION_FORM_URLENCODED));

        eventProbe.counterMetric(DVAD_TOKEN_REQUEST_CREATED.withEndpointPrefix());

        final HTTPReply httpReply;
        String requestURIString = requestURI.toString();
        LOGGER.debug("Token request endpoint is {}", requestURIString);
        LOGGER.info("Submitting token request to third party...");
        stopWatch.start();
        try (CloseableHttpResponse response = closeableHttpClient.execute(request)) {

            eventProbe.counterMetric(DVAD_TOKEN_REQUEST_SEND_OK.withEndpointPrefix());

            // throws OAuthErrorResponseException on error
            httpReply =
                    HTTPReplyHelper.retrieveStatusCodeAndBodyFromResponse(response, ENDPOINT_NAME);
        } catch (IOException e) {
            // No Response Latency
            eventProbe.counterMetric(
                    DVAD_TOKEN_RESPONSE_LATENCY.withEndpointPrefix(), stopWatch.stop());

            LOGGER.error("IOException executing token request - {}", e.getMessage());

            eventProbe.counterMetric(
                    DVAD_TOKEN_REQUEST_SEND_ERROR.withEndpointPrefixAndExceptionName(e));

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.ERROR_INVOKING_THIRD_PARTY_API_TOKEN_ENDPOINT);
        }

        // Response Latency
        eventProbe.counterMetric(
                DVAD_TOKEN_RESPONSE_LATENCY.withEndpointPrefix(), stopWatch.stop());

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
            LOGGER.error(
                    "Token response status code {} content - {}",
                    httpReply.statusCode,
                    httpReply.responseBody);

            eventProbe.counterMetric(
                    DVAD_TOKEN_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS.withEndpointPrefix());

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.ERROR_TOKEN_ENDPOINT_RETURNED_UNEXPECTED_HTTP_STATUS_CODE);
        }
    }

    private void assertAccessTokenResponseIsValid(AccessTokenResponse accessTokenResponse)
            throws OAuthErrorResponseException {

        String tokenType = accessTokenResponse.tokenType();
        long tokenLifetime = accessTokenResponse.expiresIn();

        if (!tokenType.equals(BEARER_TOKEN_TYPE)) {
            LOGGER.error(
                    "Access Token TokenType {} is not of type {}", tokenType, BEARER_TOKEN_TYPE);

            eventProbe.counterMetric(DVAD_TOKEN_RESPONSE_TYPE_INVALID.withEndpointPrefix());

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_VERIFY_ACCESS_TOKEN);
        }

        if (tokenLifetime <= 0 || tokenLifetime > MAX_ALLOWED_ACCESS_TOKEN_LIFETIME_SECONDS) {
            LOGGER.error(
                    "Access Token Lifetime is invalid - value {}, min 1, max {}",
                    tokenLifetime,
                    MAX_ALLOWED_ACCESS_TOKEN_LIFETIME_SECONDS);

            eventProbe.counterMetric(DVAD_TOKEN_RESPONSE_TYPE_INVALID.withEndpointPrefix());

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_VERIFY_ACCESS_TOKEN);
        }

        // No exceptions Token response is seen as valid
        eventProbe.counterMetric(DVAD_TOKEN_RESPONSE_TYPE_VALID.withEndpointPrefix());
    }
}
