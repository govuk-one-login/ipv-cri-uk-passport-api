package uk.gov.di.ipv.cri.passport.library.dvad.services;

import org.apache.http.HttpException;
import org.apache.http.impl.client.CloseableHttpClient;
import uk.gov.account.ipv.cri.lime.limeade.service.http.CloseableHttpClientFactory;
import uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters;
import uk.gov.di.ipv.cri.passport.library.exceptions.HttpClientException;
import uk.gov.di.ipv.cri.passport.library.service.ApacheHTTPClientFactoryService;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

public class DVADCloseableHttpClientFactory {
    public static final String MAP_KEY_TLS_CERT = "TLSCert-11-09-2025";
    public static final String MAP_KEY_TLS_KEY = "TLSKey-11-09-2025";
    public static final String MAP_KEY_TLS_ROOT_CERT = "TLSRootCertificate";
    public static final String MAP_KEY_TLS_INT_CERT = "TLSIntermediateCertificate-24-09-2024";

    public CloseableHttpClient getClient(
            boolean tlsOn, ParameterStoreService parameterStoreService) {
        try {
            if (tlsOn) {
                Map<String, String> dvadHtpClientCertsKeysMap =
                        parameterStoreService.getAllParametersFromPathWithDecryption(
                                ParameterStoreParameters.HMPO_HTTP_CLIENT_PARAMETER_PATH);

                final String base64TLSCertString = dvadHtpClientCertsKeysMap.get(MAP_KEY_TLS_CERT);

                final String base64TLSKeyString = dvadHtpClientCertsKeysMap.get(MAP_KEY_TLS_KEY);

                final String base64TLSRootCertString =
                        dvadHtpClientCertsKeysMap.get(MAP_KEY_TLS_ROOT_CERT);

                final String base64TLSIntCertString =
                        dvadHtpClientCertsKeysMap.get(MAP_KEY_TLS_INT_CERT);

                return ApacheHTTPClientFactoryService.generateMTLSHttpClient(
                        base64TLSCertString,
                        base64TLSKeyString,
                        base64TLSRootCertString,
                        base64TLSIntCertString);
            } else {
                return CloseableHttpClientFactory.generateTLSHttpClient();
            }
        } catch (NoSuchAlgorithmException
                | InvalidKeySpecException
                | CertificateException
                | KeyStoreException
                | IOException
                | UnrecoverableKeyException
                | KeyManagementException
                | HttpException e) {
            throw new HttpClientException(e);
        }
    }
}
