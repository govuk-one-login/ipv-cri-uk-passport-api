package uk.gov.di.ipv.cri.passport.checkpassport.util;

import org.apache.http.HttpResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.util.dvad.responses.HttpResponseFixtures.createHttpResponse;

@ExtendWith(MockitoExtension.class)
class HTTPReplyHelperTest {

    private final String ENDPOINT_NAME = "Test Endpoint";
    private final String NO_BODY_TEXT_FORMAT = "No %s response body text found";

    @Test
    void shouldSetNoBodyTextWhenEntityUtilsReturnsNull() throws OAuthErrorResponseException {

        int expectedStatusCode = 200;
        String expectedBodyContent = String.format(NO_BODY_TEXT_FORMAT, ENDPOINT_NAME);

        HttpResponse mockResponse = createHttpResponse(expectedStatusCode, null, false);

        HTTPReply reply =
                HTTPReplyHelper.retrieveStatusCodeAndBodyFromResponse(mockResponse, ENDPOINT_NAME);

        assertEquals(expectedBodyContent, reply.responseBody);
        assertEquals(expectedStatusCode, reply.statusCode);
    }

    @Test
    void shouldThrowOAuthHttpResponseExceptionWhenIOExceptionEncounteredRetrievingHTTPReply() {

        HttpResponse mockResponse = createHttpResponse(200, null, true);

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () ->
                                HTTPReplyHelper.retrieveStatusCodeAndBodyFromResponse(
                                        mockResponse, ENDPOINT_NAME));

        assertEquals("Failed to retrieve http response body", thrownException.getErrorReason());
    }
}
