package uk.gov.di.ipv.cri.passport.checkpassport.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.DcsResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.ThirdPartyAPIResult;
import uk.gov.di.ipv.cri.passport.checkpassport.exception.IpvCryptoException;
import uk.gov.di.ipv.cri.passport.checkpassport.exception.OAuthHttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;

import java.io.IOException;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_POST_URL;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.THIRD_PARTY_API_RESPONSE_TYPE_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.THIRD_PARTY_API_RESPONSE_TYPE_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.THIRD_PARTY_API_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.THIRD_PARTY_REQUEST_CREATED;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.THIRD_PARTY_REQUEST_SEND_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.THIRD_PARTY_REQUEST_SEND_OK;

public class ThirdPartyAPIService {

    private static final Logger LOGGER = LogManager.getLogger();

    private final EventProbe eventProbe;

    private final DcsCryptographyService dcsCryptographyService;
    private final PassportConfigurationService passportConfigurationService;
    private HttpClient httpClient;

    public ThirdPartyAPIService(
            PassportConfigurationService passportConfigurationService,
            EventProbe eventProbe,
            DcsCryptographyService dcsCryptographyService,
            HttpClient httpClient) {

        this.passportConfigurationService = passportConfigurationService;
        this.eventProbe = eventProbe;
        this.dcsCryptographyService = dcsCryptographyService;
        this.httpClient = httpClient;
    }

    public ThirdPartyAPIResult performCheck(PassportFormData passportFormData)
            throws OAuthHttpResponseExceptionWithErrorBody {
        LOGGER.info("Mapping person to third party document check request");

        HttpPost request;
        try {
            JWSObject preparedDcsPayload = dcsCryptographyService.preparePayload(passportFormData);
            String requestBody = preparedDcsPayload.serialize();
            URI endpoint = URI.create(passportConfigurationService.getParameterValue(DCS_POST_URL));
            request = requestBuilder(endpoint, requestBody);
        } catch (CertificateException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | JOSEException
                | JsonProcessingException
                | IpvCryptoException e) {
            LOGGER.error(("Failed to prepare payload for DCS: " + e.getMessage()));
            throw new OAuthHttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PREPARE_DCS_PAYLOAD);
        }
        eventProbe.counterMetric(THIRD_PARTY_REQUEST_CREATED);

        CloseableHttpResponse response;
        try {
            LOGGER.info("Submitting document check request to third party...");
            response = (CloseableHttpResponse) httpClient.execute(request);
            eventProbe.counterMetric(THIRD_PARTY_REQUEST_SEND_OK);
        } catch (IOException e) {
            LOGGER.info("IOException executing http request");
            eventProbe.counterMetric(THIRD_PARTY_REQUEST_SEND_ERROR);
            throw new OAuthHttpResponseExceptionWithErrorBody(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.ERROR_INVOKING_THIRD_PARTY_API);
        }

        String responseBody;
        int statusCode;

        try {
            String mappedBody = EntityUtils.toString(response.getEntity());

            // EntityUtils can return null
            responseBody = (mappedBody) == null ? "No Body Text Found" : mappedBody;

            statusCode = response.getStatusLine().getStatusCode();
        } catch (IOException e) {
            LOGGER.error("IOException mapping http response body");
            throw new OAuthHttpResponseExceptionWithErrorBody(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_MAP_HTTP_RESPONSE_BODY);
        }

        return thirdPartyAPIResponseHandler(statusCode, responseBody);
    }

    private ThirdPartyAPIResult thirdPartyAPIResponseHandler(int statusCode, String responseBody)
            throws OAuthHttpResponseExceptionWithErrorBody {

        if (statusCode == 200) {
            LOGGER.info("Third party response code {}", statusCode);

            DcsResponse unwrappedDcsResponse;
            try {
                unwrappedDcsResponse = dcsCryptographyService.unwrapDcsResponse(responseBody);
            } catch (IpvCryptoException e) {

                // IpvCryptoException is seen when a signing cert has expired
                // and all message signatures fail verification
                LOGGER.error(e.getMessage());
                // TODO If the object mapper fails in unwrapDcsResponse, check exception message for
                // possible PII
                // The first two message are safe and use-full

                throw new OAuthHttpResponseExceptionWithErrorBody(
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_UNWRAP_DCS_RESPONSE);
            } catch (CertificateException | ParseException | JOSEException e) {

                // TODO review exceptions for PII
                LOGGER.error(e.getMessage());

                throw new OAuthHttpResponseExceptionWithErrorBody(
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_UNWRAP_DCS_RESPONSE);
            }

            // isError flag is non-recoverable
            if (unwrappedDcsResponse.isError()) {
                String errorMessage = unwrappedDcsResponse.getErrorMessage().toString();
                LOGGER.error("DCS encountered an error: {}", errorMessage);

                eventProbe.counterMetric(
                        THIRD_PARTY_API_RESPONSE_TYPE_ERROR); // A Specific Error from API

                throw new OAuthHttpResponseExceptionWithErrorBody(
                        HttpStatusCode.INTERNAL_SERVER_ERROR, ErrorResponse.DCS_RETURNED_AN_ERROR);
            }

            ThirdPartyAPIResult thirdPartyAPIResult = new ThirdPartyAPIResult();
            thirdPartyAPIResult.setTransactionId(unwrappedDcsResponse.getRequestId());
            thirdPartyAPIResult.setValid(unwrappedDcsResponse.isValid());

            LOGGER.info("Third party response successfully mapped");
            eventProbe.counterMetric(THIRD_PARTY_API_RESPONSE_TYPE_OK);

            return thirdPartyAPIResult;
        } else {

            LOGGER.error(
                    "Third party replied with HTTP status code {}, response text: {}",
                    statusCode,
                    responseBody);

            eventProbe.counterMetric(THIRD_PARTY_API_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS);

            if (statusCode >= 300 && statusCode <= 399) {
                // Not Seen
                throw new OAuthHttpResponseExceptionWithErrorBody(
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        ErrorResponse.THIRD_PARTY_ERROR_HTTP_30X);
            } else if (statusCode >= 400 && statusCode <= 499) {
                // Seen when a cert has expired
                throw new OAuthHttpResponseExceptionWithErrorBody(
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        ErrorResponse.THIRD_PARTY_ERROR_HTTP_40X);
            } else if (statusCode >= 500 && statusCode <= 599) {
                // Error on third party side
                throw new OAuthHttpResponseExceptionWithErrorBody(
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        ErrorResponse.THIRD_PARTY_ERROR_HTTP_50X);
            } else {
                // Any other status codes
                throw new OAuthHttpResponseExceptionWithErrorBody(
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        ErrorResponse.THIRD_PARTY_ERROR_HTTP_X);
            }
        }
    }

    private HttpPost requestBuilder(URI endpointUri, String requestBody) {
        HttpPost request = new HttpPost(endpointUri);
        request.addHeader("Content-Type", "application/jose");

        request.setEntity(new StringEntity(requestBody, ContentType.DEFAULT_TEXT));

        return request;
    }
}
