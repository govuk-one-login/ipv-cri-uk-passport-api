package uk.gov.di.ipv.cri.passport.library.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static uk.gov.di.ipv.cri.passport.library.CertAndKeyTestFixtures.TEST_ROOT_CRT;
import static uk.gov.di.ipv.cri.passport.library.CertAndKeyTestFixtures.TEST_TLS_KEY;

@ExtendWith(MockitoExtension.class)
class KeyCertHelperTest {

    @Test
    void shouldReturnDecodedX509Certificate() {

        AtomicReference<Certificate> cert = new AtomicReference<>();
        assertDoesNotThrow(() -> cert.set(KeyCertHelper.getDecodedX509Certificate(TEST_ROOT_CRT)));
        assertNotNull(cert.get());
    }

    @Test
    void shouldReturnDecodedPrivateRSAKey() {
        AtomicReference<PrivateKey> key = new AtomicReference<>();
        assertDoesNotThrow(() -> key.set(KeyCertHelper.getDecodedPrivateRSAKey(TEST_TLS_KEY)));
        assertNotNull(key.get());
    }
}
