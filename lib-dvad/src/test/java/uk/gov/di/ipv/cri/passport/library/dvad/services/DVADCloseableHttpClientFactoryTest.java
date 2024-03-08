package uk.gov.di.ipv.cri.passport.library.dvad.services;

import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters;
import uk.gov.di.ipv.cri.passport.library.service.ClientFactoryService;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.CertAndKeyTestFixtures.TEST_ROOT_CRT;
import static uk.gov.di.ipv.cri.passport.library.CertAndKeyTestFixtures.TEST_TLS_CRT;
import static uk.gov.di.ipv.cri.passport.library.CertAndKeyTestFixtures.TEST_TLS_KEY;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class DVADCloseableHttpClientFactoryTest {

    @SystemStub private EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Mock private ParameterStoreService mockParameterStoreService;

    @BeforeEach
    void setUp() {
        environmentVariables.set("AWS_REGION", "eu-west-2");
        environmentVariables.set("AWS_STACK_NAME", "TEST_STACK");
    }

    @ParameterizedTest
    @CsvSource({
        "true", "false",
    })
    void shouldGetClientFromDVADCloseableHttpClientFactory(boolean tlsOn) {
        DVADCloseableHttpClientFactory dvadCloseableHttpClientFactory =
                new DVADCloseableHttpClientFactory();

        if (tlsOn) {
            Map<String, String> testParameterMap =
                    Map.of(
                            DVADCloseableHttpClientFactory.MAP_KEY_TLS_CERT,
                            TEST_TLS_CRT,
                            DVADCloseableHttpClientFactory.MAP_KEY_TLS_KEY,
                            TEST_TLS_KEY,
                            DVADCloseableHttpClientFactory.MAP_KEY_TLS_ROOT_CERT,
                            TEST_ROOT_CRT,
                            DVADCloseableHttpClientFactory.MAP_KEY_TLS_INT_CERT,
                            TEST_TLS_CRT);

            when(mockParameterStoreService.getAllParametersFromPathWithDecryption(
                            ParameterStoreParameters.HMPO_HTTP_CLIENT_PARAMETER_PATH))
                    .thenReturn(testParameterMap);
        }

        CloseableHttpClient closeableHttpClient =
                assertDoesNotThrow(
                        () ->
                                dvadCloseableHttpClientFactory.getClient(
                                        tlsOn,
                                        mockParameterStoreService,
                                        new ClientFactoryService()));

        assertNotNull(closeableHttpClient);
    }
}
