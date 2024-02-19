package uk.gov.di.ipv.cri.passport.library.service;

import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import uk.gov.di.ipv.cri.passport.library.exceptions.HttpClientException;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.CertAndKeyTestFixtures.TEST_ROOT_CRT;
import static uk.gov.di.ipv.cri.passport.library.CertAndKeyTestFixtures.TEST_TLS_CRT;
import static uk.gov.di.ipv.cri.passport.library.CertAndKeyTestFixtures.TEST_TLS_KEY;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_HTTPCLIENT_TLS_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_HTTPCLIENT_TLS_INTER_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_HTTPCLIENT_TLS_KEY;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_HTTPCLIENT_TLS_ROOT_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_HTTPCLIENT_TLS_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_HTTPCLIENT_TLS_INTER_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_HTTPCLIENT_TLS_KEY;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_HTTPCLIENT_TLS_ROOT_CERT;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class ClientFactoryServiceTest {
    @SystemStub private EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Mock private ParameterStoreService mockParameterStoreService;

    private ClientFactoryService clientFactoryService;

    @BeforeEach
    void setUp() {
        environmentVariables.set("AWS_REGION", "eu-west-2");
        environmentVariables.set("AWS_STACK_NAME", "TEST_STACK");

        clientFactoryService = new ClientFactoryService();
    }

    @Test
    void shouldReturnKMSClient() {

        KmsClient kmsClient = clientFactoryService.getKMSClient();

        assertNotNull(kmsClient);
    }

    @Test
    void shouldReturnSSMProvider() {

        SSMProvider ssmProvider = clientFactoryService.getSSMProvider();

        assertNotNull(ssmProvider);
    }

    @Test
    void shouldReturnSqsClient() {

        SqsClient sqsClient = clientFactoryService.getSqsClient();

        assertNotNull(sqsClient);
    }

    @Test
    void shouldReturnLegacyHTTPClientWithNoSSL() {

        CloseableHttpClient closeableHttpClient =
                clientFactoryService.getLegacyCloseableHttpClient(false, mockParameterStoreService);

        assertNotNull(closeableHttpClient);
    }

    @Test
    void shouldReturnHttpClientWithNoSSL() {

        CloseableHttpClient closeableHttpClient =
                clientFactoryService.getCloseableHttpClient(false, mockParameterStoreService);

        assertNotNull(closeableHttpClient);
    }

    @Test
    void shouldReturnClientWithRegionManuallySet() {
        ClientFactoryService clientFactoryServiceManual =
                new ClientFactoryService(Region.EU_WEST_2);

        assertNotNull(clientFactoryServiceManual);
    }

    @Test
    void shouldReturnLegacyHTTPClientWithSSL() {

        when(mockParameterStoreService.getEncryptedParameterValue(DCS_HTTPCLIENT_TLS_CERT))
                .thenReturn(TEST_TLS_CRT);
        when(mockParameterStoreService.getEncryptedParameterValue(DCS_HTTPCLIENT_TLS_KEY))
                .thenReturn(TEST_TLS_KEY);
        when(mockParameterStoreService.getEncryptedParameterValue(DCS_HTTPCLIENT_TLS_ROOT_CERT))
                .thenReturn(TEST_ROOT_CRT);
        when(mockParameterStoreService.getEncryptedParameterValue(DCS_HTTPCLIENT_TLS_INTER_CERT))
                .thenReturn(TEST_TLS_CRT);

        CloseableHttpClient closeableHttpClient =
                clientFactoryService.getLegacyCloseableHttpClient(true, mockParameterStoreService);

        assertNotNull(closeableHttpClient);
    }

    @ParameterizedTest
    @CsvSource({
        "CertificateException, true",
        "CertificateException, false",
        "InvalidKeySpecException, true",
        "InvalidKeySpecException, false"
    })
    void shouldCatchExceptionAndThrowHttpClientExceptionForExceptionsGettingHttpClient(
            String exceptionName, boolean legaccy) {

        String badData = new String(Base64.getEncoder().encode("TEST1234".getBytes()));

        HttpClientException expectedReturnedException = null;

        switch (exceptionName) {
            case "CertificateException":
                expectedReturnedException = new HttpClientException(new CertificateException());

                if (legaccy) {
                    when(mockParameterStoreService.getEncryptedParameterValue(
                                    DCS_HTTPCLIENT_TLS_CERT))
                            .thenReturn(badData);
                } else {
                    when(mockParameterStoreService.getEncryptedParameterValue(
                                    HMPO_HTTPCLIENT_TLS_CERT))
                            .thenReturn(badData);
                }

                break;
            case "InvalidKeySpecException":
                if (legaccy) {
                    when(mockParameterStoreService.getEncryptedParameterValue(
                                    DCS_HTTPCLIENT_TLS_CERT))
                            .thenReturn(TEST_TLS_CRT);
                    when(mockParameterStoreService.getEncryptedParameterValue(
                                    DCS_HTTPCLIENT_TLS_KEY))
                            .thenReturn(badData);
                } else {
                    when(mockParameterStoreService.getEncryptedParameterValue(
                                    HMPO_HTTPCLIENT_TLS_CERT))
                            .thenReturn(TEST_TLS_CRT);
                    when(mockParameterStoreService.getEncryptedParameterValue(
                                    HMPO_HTTPCLIENT_TLS_KEY))
                            .thenReturn(badData);
                }

                expectedReturnedException = new HttpClientException(new InvalidKeySpecException());
                break;
        }

        HttpClientException thrownException;
        if (legaccy) {

            thrownException =
                    assertThrows(
                            HttpClientException.class,
                            () ->
                                    clientFactoryService.getLegacyCloseableHttpClient(
                                            true, mockParameterStoreService),
                            "An Error Message");
        } else {
            thrownException =
                    assertThrows(
                            HttpClientException.class,
                            () ->
                                    clientFactoryService.getCloseableHttpClient(
                                            true, mockParameterStoreService),
                            "An Error Message");
        }

        assert expectedReturnedException != null;
        assertEquals(expectedReturnedException.getClass(), thrownException.getClass());
    }

    @Test
    void shouldReturnHTTPClientWithSSL() {

        when(mockParameterStoreService.getEncryptedParameterValue(HMPO_HTTPCLIENT_TLS_CERT))
                .thenReturn(TEST_TLS_CRT);
        when(mockParameterStoreService.getEncryptedParameterValue(HMPO_HTTPCLIENT_TLS_KEY))
                .thenReturn(TEST_TLS_KEY);
        when(mockParameterStoreService.getEncryptedParameterValue(HMPO_HTTPCLIENT_TLS_ROOT_CERT))
                .thenReturn(TEST_ROOT_CRT);
        when(mockParameterStoreService.getEncryptedParameterValue(HMPO_HTTPCLIENT_TLS_INTER_CERT))
                .thenReturn(TEST_TLS_CRT);

        CloseableHttpClient closeableHttpClient =
                clientFactoryService.getCloseableHttpClient(true, mockParameterStoreService);

        assertNotNull(closeableHttpClient);
    }
}
