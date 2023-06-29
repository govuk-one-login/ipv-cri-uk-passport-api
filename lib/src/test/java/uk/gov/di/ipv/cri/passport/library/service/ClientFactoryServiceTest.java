package uk.gov.di.ipv.cri.passport.library.service;

import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.ssm.SsmClient;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import static org.junit.jupiter.api.Assertions.assertNotNull;
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

    @Mock private PassportConfigurationService mockPassportConfigurationService;

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
    void shouldReturnSsmClient() {

        SsmClient ssmClient = clientFactoryService.getSsmClient();

        assertNotNull(ssmClient);
    }

    @Test
    void shouldReturnSqsClient() {

        SqsClient sqsClient = clientFactoryService.getSqsClient();

        assertNotNull(sqsClient);
    }

    @Test
    void shouldReturnLegacyHTTPClientWithNoSSL() {

        CloseableHttpClient closeableHttpClient =
                clientFactoryService.getLegacyCloseableHttpClient(
                        false, mockPassportConfigurationService);

        assertNotNull(closeableHttpClient);
    }

    @Test
    void shouldReturnHttpClientWithNoSSL() {

        CloseableHttpClient closeableHttpClient =
                clientFactoryService.getCloseableHttpClient(
                        false, mockPassportConfigurationService);

        assertNotNull(closeableHttpClient);
    }

    @Test
    void shouldReturnLegacyHTTPClientWithSSL() {

        when(mockPassportConfigurationService.getEncryptedSsmParameter(DCS_HTTPCLIENT_TLS_CERT))
                .thenReturn(TEST_TLS_CRT);
        when(mockPassportConfigurationService.getEncryptedSsmParameter(DCS_HTTPCLIENT_TLS_KEY))
                .thenReturn(TEST_TLS_KEY);
        when(mockPassportConfigurationService.getEncryptedSsmParameter(
                        DCS_HTTPCLIENT_TLS_ROOT_CERT))
                .thenReturn(TEST_ROOT_CRT);
        when(mockPassportConfigurationService.getEncryptedSsmParameter(
                        DCS_HTTPCLIENT_TLS_INTER_CERT))
                .thenReturn(TEST_TLS_CRT);

        CloseableHttpClient closeableHttpClient =
                clientFactoryService.getLegacyCloseableHttpClient(
                        true, mockPassportConfigurationService);

        assertNotNull(closeableHttpClient);
    }

    @Test
    void shouldReturnHTTPClientWithSSL() {

        when(mockPassportConfigurationService.getEncryptedSsmParameter(HMPO_HTTPCLIENT_TLS_CERT))
                .thenReturn(TEST_TLS_CRT);
        when(mockPassportConfigurationService.getEncryptedSsmParameter(HMPO_HTTPCLIENT_TLS_KEY))
                .thenReturn(TEST_TLS_KEY);
        when(mockPassportConfigurationService.getEncryptedSsmParameter(
                        HMPO_HTTPCLIENT_TLS_ROOT_CERT))
                .thenReturn(TEST_ROOT_CRT);
        when(mockPassportConfigurationService.getEncryptedSsmParameter(
                        HMPO_HTTPCLIENT_TLS_INTER_CERT))
                .thenReturn(TEST_TLS_CRT);

        CloseableHttpClient closeableHttpClient =
                clientFactoryService.getCloseableHttpClient(true, mockPassportConfigurationService);

        assertNotNull(closeableHttpClient);
    }
}
