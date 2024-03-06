package uk.gov.di.ipv.cri.passport.library.service;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;
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
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

// See https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/http-configuration.html
// If an explicit client choice is not made the SDK default will be used *if it is the only one* in
// the
// classpath
// If there is more than one of the same HTTP client type a conflict will occur for these clients.
// To prevent this, the exact http clients are now being specified for each client.
// DataStore (Dynamo) from CRI-lib his has this already done in CRI lib.
public class ClientFactoryService {
    private static final Logger LOGGER = LogManager.getLogger();

    private final Region awsRegion;

    // Used internally at runtime when loading/retrieving keys into/from the SSL Keystore
    private static final char[] RANDOM_RUN_TIME_KEYSTORE_PASSWORD =
            UUID.randomUUID().toString().toCharArray();

    // https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/best-practices.html#bestpractice1
    private static final SdkHttpClient sdkHttpClient = UrlConnectionHttpClient.create();

    public ClientFactoryService() {
        awsRegion = Region.of(System.getenv("AWS_REGION"));
    }

    public ClientFactoryService(Region awsRegion) {
        this.awsRegion = awsRegion;
    }

    public KmsClient getKMSClient() {
        return KmsClient.builder()
                .region(awsRegion)
                .httpClient(sdkHttpClient)
                .credentialsProvider(EnvironmentVariableCredentialsProvider.create())
                .build();
    }

    public SqsClient getSqsClient() {
        return SqsClient.builder().httpClient(sdkHttpClient).region(awsRegion).build();
    }

    // ThreadLocalRandom not used cryptographically here
    @java.lang.SuppressWarnings("java:S2245")
    public SSMProvider getSSMProvider() {
        SsmClient ssmClient =
                SsmClient.builder().region(awsRegion).httpClient(sdkHttpClient).build();

        // A random cache age between 5-15 minutes (in seconds)
        // Avoids multiple scaling lambdas expiring their caches at the exact same time
        int maxCacheAge = ThreadLocalRandom.current().nextInt(900 - 300 + 1) + 300;

        LOGGER.info("PowerTools SSMProvider defaultMaxAge selected as {} seconds", maxCacheAge);

        return ParamManager.getSsmProvider(ssmClient)
                .defaultMaxAge(maxCacheAge, ChronoUnit.SECONDS);
    }

    public SecretsManagerClient getSecretsManagerClient() {
        return SecretsManagerClient.builder()
                .region(awsRegion)
                .httpClient(sdkHttpClient)
                .credentialsProvider(EnvironmentVariableCredentialsProvider.create())
                .build();
    }

    public CloseableHttpClient generatePublicHttpClient() {
        return HttpClients.custom().build();
    }

    public CloseableHttpClient generateHTTPClientFromExternalApacheHttpClient(
            String base64TLSCertString,
            String base64TLSKeyString,
            String base64TLSRootCertString,
            String base64TLSIntCertString)
            throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException,
                    KeyStoreException, IOException, UnrecoverableKeyException,
                    KeyManagementException {

        Certificate tlsCert = KeyCertHelper.getDecodedX509Certificate(base64TLSCertString);

        PrivateKey tlsKey = KeyCertHelper.getDecodedPrivateRSAKey(base64TLSKeyString);

        KeyStore keystoreTLS = createKeyStore(tlsCert, tlsKey);

        Certificate tlsRootCert = KeyCertHelper.getDecodedX509Certificate(base64TLSRootCertString);

        Certificate tlsIntCert = KeyCertHelper.getDecodedX509Certificate(base64TLSIntCertString);

        KeyStore trustStore = createTrustStore(new Certificate[] {tlsRootCert, tlsIntCert});

        SSLContext sslContext = sslContextSetup(keystoreTLS, trustStore);

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
