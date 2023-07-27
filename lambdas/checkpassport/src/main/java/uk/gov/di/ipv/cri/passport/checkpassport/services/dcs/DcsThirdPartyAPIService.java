package uk.gov.di.ipv.cri.passport.checkpassport.services.dcs;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import org.apache.http.HttpStatus;
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
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dcs.DcsResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.ThirdPartyAPIResult;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.fields.APIResultSource;
import uk.gov.di.ipv.cri.passport.checkpassport.exception.dcs.IpvCryptoException;
import uk.gov.di.ipv.cri.passport.checkpassport.services.ThirdPartyAPIService;
import uk.gov.di.ipv.cri.passport.checkpassport.util.HTTPReply;
import uk.gov.di.ipv.cri.passport.checkpassport.util.HTTPReplyHelper;
import uk.gov.di.ipv.cri.passport.library.config.HttpRequestConfig;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;

import java.io.IOException;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

import static uk.gov.di.ipv.cri.passport.checkpassport.domain.result.fields.APIResultSource.DCS;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_POST_URL;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.LOG_DCS_RESPONSE;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DCS_REQUEST_CREATED;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DCS_REQUEST_SEND_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DCS_REQUEST_SEND_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DCS_RESPONSE_TYPE_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DCS_RESPONSE_TYPE_EXPECTED_HTTP_STATUS;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DCS_RESPONSE_TYPE_INVALID;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DCS_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS;
import static uk.gov.di.ipv.cri.passport.library.metrics.ThirdPartyAPIEndpointMetric.DCS_RESPONSE_TYPE_VALID;

public class DcsThirdPartyAPIService implements ThirdPartyAPIService {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final APIResultSource API_RESULT_SOURCE = DCS;

    private static final String SERVICE_NAME = DcsThirdPartyAPIService.class.getSimpleName();

    private final EventProbe eventProbe;

    private final PassportConfigurationService passportConfigurationService;

    private final CloseableHttpClient closeableHttpClient;
    private final RequestConfig defaultRequestConfig;

    private final DcsCryptographyService dcsCryptographyService;

    public DcsThirdPartyAPIService(
            PassportConfigurationService passportConfigurationService,
            EventProbe eventProbe,
            DcsCryptographyService dcsCryptographyService,
            CloseableHttpClient closeableHttpClient) {

        this.passportConfigurationService = passportConfigurationService;
        this.eventProbe = eventProbe;
        this.dcsCryptographyService = dcsCryptographyService;
        this.closeableHttpClient = closeableHttpClient;

        this.defaultRequestConfig = new HttpRequestConfig().getDefaultRequestConfig();
    }

    public String getServiceName() {
        return SERVICE_NAME;
    }

    public ThirdPartyAPIResult performCheck(PassportFormData passportFormData)
            throws OAuthErrorResponseException {
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
            throw new OAuthErrorResponseException(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PREPARE_DCS_PAYLOAD);
        }
        eventProbe.counterMetric(DCS_REQUEST_CREATED.withEndpointPrefix());

        // Enforce connection timeout values
        request.setConfig(defaultRequestConfig);

        final HTTPReply httpReply;
        LOGGER.info("Submitting document check request to third party...");
        try (CloseableHttpResponse response = closeableHttpClient.execute(request)) {
            eventProbe.counterMetric(DCS_REQUEST_SEND_OK.withEndpointPrefix());
            // throws OAuthErrorResponseException on error
            httpReply =
                    HTTPReplyHelper.retrieveStatusCodeAndBodyFromResponse(
                            response, API_RESULT_SOURCE.getName());

            if (Boolean.parseBoolean(
                    passportConfigurationService.getParameterValue(LOG_DCS_RESPONSE))) {
                LOGGER.info("DCS response {}", httpReply.responseBody);
            }
        } catch (IOException e) {
            LOGGER.error("IOException executing http request {}", e.getMessage());
            eventProbe.counterMetric(DCS_REQUEST_SEND_ERROR.withEndpointPrefix());
            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.ERROR_INVOKING_LEGACY_THIRD_PARTY_API);
        }

        ThirdPartyAPIResult thirdPartyAPIResult = thirdPartyAPIResponseHandler(httpReply);

        thirdPartyAPIResult.setApiResultSource(API_RESULT_SOURCE);

        return thirdPartyAPIResult;
    }

    private ThirdPartyAPIResult thirdPartyAPIResponseHandler(HTTPReply httpReply)
            throws OAuthErrorResponseException {

        if (httpReply.statusCode == 200) {
            LOGGER.info("Third party response code {}", httpReply.statusCode);

            eventProbe.counterMetric(DCS_RESPONSE_TYPE_EXPECTED_HTTP_STATUS.withEndpointPrefix());

            DcsResponse unwrappedDcsResponse;
            try {
                unwrappedDcsResponse =
                        dcsCryptographyService.unwrapDcsResponse(httpReply.responseBody);
            } catch (IpvCryptoException e) {

                // Thrown from unwrapDcsResponse - IpvCryptoException (CRI internal exception) is
                // seen when a signing cert has expired and all message signatures fail verification
                // will also occur if object mapping fails and may contain all response PII
                // TODO break unwrapDcsResponse into stages to allow testing and suppress PII
                LOGGER.error(e.getMessage());

                eventProbe.counterMetric(DCS_RESPONSE_TYPE_INVALID.withEndpointPrefix());

                throw new OAuthErrorResponseException(
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_UNWRAP_DCS_RESPONSE);
            } catch (CertificateException | ParseException | JOSEException e) {

                // Thrown from unwrapDcsResponse -
                // TODO rework unwrapDcsResponse into stages and review these exceptions for PII

                LOGGER.error(e.getMessage());

                eventProbe.counterMetric(DCS_RESPONSE_TYPE_INVALID.withEndpointPrefix());

                throw new OAuthErrorResponseException(
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_UNWRAP_DCS_RESPONSE);
            }

            // isError flag is non-recoverable
            if (unwrappedDcsResponse.isError()) {

                // Logging null as errorMessage if ever null is intended
                String errorMessage = null;
                if (unwrappedDcsResponse.getErrorMessage() != null) {
                    errorMessage = unwrappedDcsResponse.getErrorMessage().toString();
                }

                LOGGER.error("DCS encountered an error: {}", errorMessage);

                eventProbe.counterMetric(
                        DCS_RESPONSE_TYPE_ERROR.withEndpointPrefix()); // A Specific Error from API

                throw new OAuthErrorResponseException(
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        ErrorResponse.DCS_RETURNED_AN_ERROR_RESPONSE);
            }

            ThirdPartyAPIResult thirdPartyAPIResult = new ThirdPartyAPIResult();
            thirdPartyAPIResult.setTransactionId(unwrappedDcsResponse.getRequestId());
            thirdPartyAPIResult.setValid(unwrappedDcsResponse.isValid());
            LOGGER.info("Third party response Valid");
            eventProbe.counterMetric(DCS_RESPONSE_TYPE_VALID.withEndpointPrefix());

            return thirdPartyAPIResult;
        } else {

            LOGGER.error(
                    "Third party replied with Unexpected HTTP status code {}, response text: {}",
                    httpReply.statusCode,
                    httpReply.responseBody);

            eventProbe.counterMetric(DCS_RESPONSE_TYPE_UNEXPECTED_HTTP_STATUS.withEndpointPrefix());

            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.ERROR_DCS_RETURNED_UNEXPECTED_HTTP_STATUS_CODE);
        }
    }

    private HttpPost requestBuilder(URI endpointUri, String requestBody) {
        HttpPost request = new HttpPost(endpointUri);
        request.addHeader("Content-Type", "application/jose");

        request.setEntity(new StringEntity(requestBody, ContentType.DEFAULT_TEXT));

        return request;
    }
}
