package uk.gov.di.ipv.cri.passport.certexpiryreminder.handler.config;

import uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters;
import uk.gov.di.ipv.cri.passport.library.dvad.services.DVADCloseableHttpClientFactory;
import uk.gov.di.ipv.cri.passport.library.helpers.KeyCertHelper;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

public class CertExpiryReminderConfig {

    private ParameterStoreService parameterStoreService;

    public CertExpiryReminderConfig(ParameterStoreService parameterStoreService) {
        this.parameterStoreService = parameterStoreService;
    }

    public Map<String, X509Certificate> getHMPOCertificates() throws CertificateException {

        Map<String, String> dvadHtpClientCertsKeysMap =
                parameterStoreService.getAllParametersFromPathWithDecryption(
                        ParameterStoreParameters.HMPO_HTTP_CLIENT_PARAMETER_PATH);

        final String base64TLSCertString =
                dvadHtpClientCertsKeysMap.get(DVADCloseableHttpClientFactory.MAP_KEY_TLS_CERT);

        final String base64TLSIntCertString =
                dvadHtpClientCertsKeysMap.get(DVADCloseableHttpClientFactory.MAP_KEY_TLS_INT_CERT);

        final String base64TLSRootCertString =
                dvadHtpClientCertsKeysMap.get(DVADCloseableHttpClientFactory.MAP_KEY_TLS_ROOT_CERT);

        X509Certificate tlsCertExpiry =
                KeyCertHelper.getDecodedX509Certificate(base64TLSCertString);

        X509Certificate tlsRootCertExpiry =
                KeyCertHelper.getDecodedX509Certificate(base64TLSRootCertString);

        X509Certificate tlsIntermediateCertExpiry =
                KeyCertHelper.getDecodedX509Certificate(base64TLSIntCertString);

        return Map.of(
                DVADCloseableHttpClientFactory.MAP_KEY_TLS_CERT,
                tlsCertExpiry,
                DVADCloseableHttpClientFactory.MAP_KEY_TLS_INT_CERT,
                tlsIntermediateCertExpiry,
                DVADCloseableHttpClientFactory.MAP_KEY_TLS_ROOT_CERT,
                tlsRootCertExpiry);
    }
}
