package uk.gov.di.ipv.cri.passport.library.dvad.util.responses;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.methods.CloseableHttpResponse;
import uk.gov.di.ipv.cri.passport.library.HttpResponseFixtures;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.AccessTokenResponse;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.GraphQLAPIResponse;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.HealthCheckResponse;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields.ResponseData;

import java.io.IOException;
import java.util.UUID;

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

        return HttpResponseFixtures.createHttpResponse(statusCode, responseBody, false);
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

        return HttpResponseFixtures.createHttpResponse(statusCode, responseBody, false);
    }

    public static CloseableHttpResponse mockGraphQLAPIResponse(int statusCode, boolean validBody)
            throws IOException {

        ResponseData responseData = ResponseDataGenerator.createValidationResultTrueResponseData();

        GraphQLAPIResponse response = GraphQLAPIResponse.builder().data(responseData).build();

        String responseBody =
                validBody ? new ObjectMapper().writeValueAsString(response) : INVALID_JSON;

        return HttpResponseFixtures.createHttpResponse(statusCode, responseBody, false);
    }
}
