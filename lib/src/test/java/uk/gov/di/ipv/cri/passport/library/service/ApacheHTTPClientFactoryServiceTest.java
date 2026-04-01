package uk.gov.di.ipv.cri.passport.library.service;

import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.ipv.cri.passport.library.CertAndKeyTestFixtures.TEST_ROOT_CRT;
import static uk.gov.di.ipv.cri.passport.library.CertAndKeyTestFixtures.TEST_TLS_CRT;
import static uk.gov.di.ipv.cri.passport.library.CertAndKeyTestFixtures.TEST_TLS_KEY;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class ApacheHTTPClientFactoryServiceTest {
    @SystemStub private EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @BeforeEach
    void setUp() {
        environmentVariables.set("AWS_REGION", "eu-west-2");
        environmentVariables.set("AWS_STACK_NAME", "TEST_STACK");
    }

    @ParameterizedTest
    @CsvSource({
        "CertificateException",
        "CertificateException",
        "InvalidKeySpecException",
        "InvalidKeySpecException"
    })
    void shouldCatchExceptionAndThrowHttpClientExceptionForExceptionsGettingHttpClient(
            String exceptionName) {
        String base64TLSCertString = TEST_TLS_CRT;
        String base64TLSKeyString = TEST_TLS_KEY;
        String base64TLSRootCertString = TEST_ROOT_CRT;
        String base64TLSIntCertString = TEST_TLS_CRT;

        String badData = new String(Base64.getEncoder().encode("TEST1234".getBytes()));

        Class<? extends Throwable> expectedExceptionClass =
                switch (exceptionName) {
                    case "CertificateException" -> {
                        base64TLSCertString = badData;
                        yield CertificateException.class;
                    }
                    case "InvalidKeySpecException" -> {
                        base64TLSKeyString = badData;
                        yield InvalidKeySpecException.class;
                    }
                    default ->
                            throw new IllegalStateException("Unexpected value: " + exceptionName);
                };

        String finalBase64TLSCertString = base64TLSCertString;
        String finalBase64TLSKeyString = base64TLSKeyString;
        Throwable thrownException =
                assertThrows(
                        expectedExceptionClass,
                        () ->
                                ApacheHTTPClientFactoryService.generateMTLSHttpClient(
                                        finalBase64TLSCertString,
                                        finalBase64TLSKeyString,
                                        base64TLSRootCertString,
                                        base64TLSIntCertString),
                        "An Error Message");

        assertNotNull(expectedExceptionClass);
        assertEquals(expectedExceptionClass, thrownException.getClass());
    }

    @Test
    void shouldReturnHTTPClientWithSSL() {
        CloseableHttpClient closeableHttpClient =
                assertDoesNotThrow(
                        () ->
                                ApacheHTTPClientFactoryService.generateMTLSHttpClient(
                                        TEST_TLS_CRT, TEST_TLS_KEY, TEST_ROOT_CRT, TEST_TLS_CRT));

        assertNotNull(closeableHttpClient);
    }
}
