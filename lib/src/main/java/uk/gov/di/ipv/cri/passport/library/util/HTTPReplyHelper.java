package uk.gov.di.ipv.cri.passport.library.util;

import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;

import java.io.IOException;

public class HTTPReplyHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(HTTPReplyHelper.class);

    private HTTPReplyHelper() {
        // Utility Class
    }

    // Small helper to avoid duplicating this code for each endpoint and api
    public static HTTPReply retrieveStatusCodeAndBodyFromResponse(
            HttpResponse response, String endpointName) throws OAuthErrorResponseException {
        try {
            String mappedBody = EntityUtils.toString(response.getEntity());

            // EntityUtils can return null
            String responseBody =
                    (mappedBody) == null
                            ? String.format("No %s response body text found", endpointName)
                            : mappedBody;
            int httpStatusCode = response.getStatusLine().getStatusCode();

            return new HTTPReply(httpStatusCode, responseBody);
        } catch (IOException e) {

            LOGGER.error("IOException retrieving {} response body", endpointName);
            LOGGER.debug(e.getMessage());

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_RETRIEVE_HTTP_RESPONSE_BODY);
        }
    }
}
