package uk.gov.di.ipv.cri.passport.certexpiryreminder.config;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.certexpiryreminder.handler.config.CertExpiryReminderConfig;
import uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters;
import uk.gov.di.ipv.cri.passport.library.dvad.services.DVADCloseableHttpClientFactory;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.CertAndKeyTestFixtures.TEST_ROOT_CRT;
import static uk.gov.di.ipv.cri.passport.library.CertAndKeyTestFixtures.TEST_TLS_CRT;
import static uk.gov.di.ipv.cri.passport.library.CertAndKeyTestFixtures.TEST_TLS_KEY;

@Tag("QualityGateUnitTest")
@ExtendWith(MockitoExtension.class)
class CertExpiryReminderConfigTest {
    @Mock private ParameterStoreService mockParameterStoreService;

    @Test
    void shouldReturnMapOfCerts() {
        CertExpiryReminderConfig certExpiryReminderConfig =
                new CertExpiryReminderConfig(mockParameterStoreService);

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

        assertDoesNotThrow(certExpiryReminderConfig::getHMPOCertificates);
    }
}
