package uk.gov.di.ipv.cri.passport.library.service;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.ssm.SsmClient;
import uk.gov.di.ipv.cri.passport.library.exceptions.HttpClientException;
import uk.gov.di.ipv.cri.passport.library.helpers.KeyCertHelper;

import javax.net.ssl.SSLContext;

import java.io.IOException;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_HTTPCLIENT_TLS_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_HTTPCLIENT_TLS_INTER_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_HTTPCLIENT_TLS_KEY;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_HTTPCLIENT_TLS_ROOT_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_HTTPCLIENT_TLS_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_HTTPCLIENT_TLS_INTER_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_HTTPCLIENT_TLS_KEY;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_HTTPCLIENT_TLS_ROOT_CERT;

// See https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/http-configuration.html
// If an explicit client choice is not made the SDK default will be used *if it the only one* in the
// classpath
// If there is more than one of the same HTTP client type a conflict will occur for these clients.
// To prevent this, the exact http clients are now being specified for each client.
// DataStore (Dynamo) from CRI-lib his has this already done in CRI lib.
public class ClientFactoryService {
    private final Region awsRegion;

    // Used internally at runtime when loading/retrieving keys into/from the SSL Keystore
    private static final char[] RANDOM_RUN_TIME_KEYSTORE_PASSWORD =
            UUID.randomUUID().toString().toCharArray();

    public ClientFactoryService() {
        awsRegion = Region.of(System.getenv("AWS_REGION"));
    }

    public KmsClient getKMSClient() {
        return KmsClient.builder()
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .region(awsRegion)
                .credentialsProvider(EnvironmentVariableCredentialsProvider.create())
                .build();
    }

    public SqsClient getSqsClient() {
        return SqsClient.builder()
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .region(awsRegion)
                .build();
    }

    public SsmClient getSsmClient() {
        return SsmClient.builder()
                .region(awsRegion)
                .httpClient(UrlConnectionHttpClient.create())
                .build();
    }

    // TODO Use Switch to SdkHttpClient instead of external http apache client
    public HttpClient getLegacyHTTPClient(
            PassportConfigurationService passportConfigurationService) {
        try {
            return generateHTTPClientFromExternalApacheHttpClient(
                    passportConfigurationService,
                    DCS_HTTPCLIENT_TLS_CERT,
                    DCS_HTTPCLIENT_TLS_KEY,
                    DCS_HTTPCLIENT_TLS_ROOT_CERT,
                    DCS_HTTPCLIENT_TLS_INTER_CERT);
        } catch (NoSuchAlgorithmException
                | InvalidKeySpecException
                | CertificateException
                | KeyStoreException
                | IOException
                | UnrecoverableKeyException
                | KeyManagementException e) {
            throw new HttpClientException(e);
        }
    }

    public HttpClient getHTTPClient(PassportConfigurationService passportConfigurationService) {
        try {
            return generateHTTPClientFromExternalApacheHttpClient(
                    passportConfigurationService,
                    HMPO_HTTPCLIENT_TLS_CERT,
                    HMPO_HTTPCLIENT_TLS_KEY,
                    HMPO_HTTPCLIENT_TLS_ROOT_CERT,
                    HMPO_HTTPCLIENT_TLS_INTER_CERT);
        } catch (NoSuchAlgorithmException
                | InvalidKeySpecException
                | CertificateException
                | KeyStoreException
                | IOException
                | UnrecoverableKeyException
                | KeyManagementException e) {
            throw new HttpClientException(e);
        }
    }

    private HttpClient generateHTTPClientFromExternalApacheHttpClient(
            PassportConfigurationService passportConfigurationService,
            String dcsHttpclientTlsCert,
            String dcsHttpclientTlsKey,
            String dcsHttpclientTlsRootCert,
            String dcsHttpclientTlsInterCert)
            throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException,
                    KeyStoreException, IOException, UnrecoverableKeyException,
                    KeyManagementException {

        String base64TLSCertString =
                passportConfigurationService.getEncryptedSsmParameter(dcsHttpclientTlsCert);
        Certificate tlsCert = KeyCertHelper.getDecodedX509Certificate(base64TLSCertString);

        String base64TLSKeyString =
                passportConfigurationService.getEncryptedSsmParameter(dcsHttpclientTlsKey);
        PrivateKey tlsKey = KeyCertHelper.getDecodedPrivateRSAKey(base64TLSKeyString);

        KeyStore keystoreTLS = createKeyStore(tlsCert, tlsKey);

        String base64TLSRootCertString =
                passportConfigurationService.getEncryptedSsmParameter(dcsHttpclientTlsRootCert);
        Certificate tlsRootCert = KeyCertHelper.getDecodedX509Certificate(base64TLSRootCertString);

        String base64TLSIntCertString =
                passportConfigurationService.getEncryptedSsmParameter(dcsHttpclientTlsInterCert);
        Certificate tlsIntCert = KeyCertHelper.getDecodedX509Certificate(base64TLSIntCertString);

        KeyStore trustStore = createTrustStore(new Certificate[] {tlsRootCert, tlsIntCert});

        SSLContext sslContext = sslContextSetup(keystoreTLS, trustStore);

        if (Boolean.parseBoolean(
                passportConfigurationService.getParameterValue("isPerformanceStub"))) {
            sslContextSetup(keystoreTLS, null);
        }

        return HttpClients.custom().setSSLContext(sslContext).build();
    }

    private SSLContext sslContextSetup(KeyStore clientTls, KeyStore caBundle)
            throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException,
                    KeyManagementException {
        return SSLContexts.custom()
                .loadKeyMaterial(clientTls, RANDOM_RUN_TIME_KEYSTORE_PASSWORD)
                .loadTrustMaterial(caBundle, null)
                .build();
    }

    private KeyStore createKeyStore(Certificate cert, Key key)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, RANDOM_RUN_TIME_KEYSTORE_PASSWORD);

        keyStore.setKeyEntry(
                "TlSKey", key, RANDOM_RUN_TIME_KEYSTORE_PASSWORD, new Certificate[] {cert});
        keyStore.setCertificateEntry("my-ca-1", cert);
        return keyStore;
    }

    private KeyStore createTrustStore(Certificate[] certificates)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        int k = 0;
        for (Certificate cert : certificates) {
            k++;
            keyStore.setCertificateEntry("my-ca-" + k, cert);
        }
        return keyStore;
    }
}
