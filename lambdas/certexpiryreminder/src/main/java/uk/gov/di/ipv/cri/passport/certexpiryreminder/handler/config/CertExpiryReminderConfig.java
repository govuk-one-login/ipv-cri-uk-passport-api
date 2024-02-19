package uk.gov.di.ipv.cri.passport.certexpiryreminder.handler.config;

import uk.gov.di.ipv.cri.passport.library.helpers.KeyCertHelper;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_HTTPCLIENT_TLS_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_HTTPCLIENT_TLS_INTER_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_HTTPCLIENT_TLS_ROOT_CERT;

public class CertExpiryReminderConfig {

    private ParameterStoreService parameterStoreService;

    public CertExpiryReminderConfig(ParameterStoreService parameterStoreService) {
        this.parameterStoreService = parameterStoreService;
    }

    public Map<String, X509Certificate> getHMPOCertificates() throws CertificateException {

        X509Certificate tlsCertExpiry =
                (X509Certificate)
                        KeyCertHelper.getDecodedX509Certificate(
                                parameterStoreService.getParameterValue(HMPO_HTTPCLIENT_TLS_CERT));
        X509Certificate tlsIntermediateCertExpiry =
                (X509Certificate)
                        KeyCertHelper.getDecodedX509Certificate(
                                parameterStoreService.getParameterValue(
                                        HMPO_HTTPCLIENT_TLS_INTER_CERT));
        X509Certificate tlsRootCertExpiry =
                (X509Certificate)
                        KeyCertHelper.getDecodedX509Certificate(
                                parameterStoreService.getParameterValue(
                                        HMPO_HTTPCLIENT_TLS_ROOT_CERT));

        return Map.of(
                HMPO_HTTPCLIENT_TLS_CERT,
                tlsCertExpiry,
                HMPO_HTTPCLIENT_TLS_INTER_CERT,
                tlsIntermediateCertExpiry,
                HMPO_HTTPCLIENT_TLS_ROOT_CERT,
                tlsRootCertExpiry);
    }
}
