package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.util.dvad.responses;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.methods.CloseableHttpResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.APIResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.AccessTokenResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.HealthCheckResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.ResponseData;

import java.io.IOException;
import java.util.UUID;

import static uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.util.dvad.responses.HttpResponseFixtures.createHttpResponse;

public class DVADResponseFixtures {

    private static final String INVALID_JSON = "}INVALID/JSON{";

    private DVADResponseFixtures() {
        throw new IllegalStateException("Test Fixtures");
    }

    /* ****************************************************************************************************
    Support Methods for Tests
    ***************************************************************************************************** */

    public static CloseableHttpResponse mockHealthCheckResponse(
            int statusCode, boolean apiIsUP, boolean validBody) throws IOException {
        HealthCheckResponse responseBodyObject =
                HealthCheckResponse.builder().status(apiIsUP ? "UP" : "DOWN").build();

        String responseBody =
                validBody
                        ? new ObjectMapper().writeValueAsString(responseBodyObject)
                        : INVALID_JSON;

        return createHttpResponse(statusCode, responseBody, false);
    }

    public static CloseableHttpResponse mockTokenResponse(
            int statusCode, String tokenType, long expiresIn, boolean validBody)
            throws IOException {

        AccessTokenResponse response =
                AccessTokenResponse.builder()
                        .accessToken(UUID.randomUUID().toString())
                        .tokenType(tokenType)
                        .expiresIn(expiresIn)
                        .build();

        String responseBody =
                validBody ? new ObjectMapper().writeValueAsString(response) : INVALID_JSON;

        return createHttpResponse(statusCode, responseBody, false);
    }

    public static CloseableHttpResponse mockGraphQLAPIResponse(int statusCode, boolean validBody)
            throws IOException {

        ResponseData responseData = ResponseDataGenerator.createValidSuccessResponseData();

        APIResponse response = APIResponse.builder().data(responseData).build();

        String responseBody =
                validBody ? new ObjectMapper().writeValueAsString(response) : INVALID_JSON;

        return createHttpResponse(statusCode, responseBody, false);
    }
}
