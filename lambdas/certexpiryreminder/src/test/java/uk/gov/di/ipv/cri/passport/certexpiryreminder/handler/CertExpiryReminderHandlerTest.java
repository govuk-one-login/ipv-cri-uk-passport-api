package uk.gov.di.ipv.cri.passport.certexpiryreminder.handler;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertExpiryReminderHandlerTest {

    @Mock private PassportConfigurationService passportConfigurationService;
    @Mock private X509Certificate mockTlsRootCert;
    @Mock private X509Certificate mockTlsIntermediateCert;
    @Mock private X509Certificate mockTlsCert;
    @Mock private EventProbe eventProbe;

    @Mock private Context context;

    private CertExpiryReminderHandler certExpiryReminderHandler;

    @BeforeEach()
    void setup() throws CertificateException {
        // The following certs are outside the expiryWindow (4 weeks)
        createCertificateMocks();

        when(passportConfigurationService.getHMPOCertificates())
                .thenReturn(
                        Map.of(
                                "tlsCert", mockTlsCert,
                                "intermediate", mockTlsIntermediateCert,
                                "tlsRoot", mockTlsRootCert));

        // Use below certificate as control for tests
        this.certExpiryReminderHandler =
                new CertExpiryReminderHandler(passportConfigurationService, eventProbe);
    }

    @Test
    void HandlerShouldIncrementMetricCountWhenCertIsCloseToExpiry() {
        Date expiry =
                Date.from(
                        LocalDate.now()
                                .atStartOfDay(ZoneId.systemDefault())
                                .plusWeeks(3)
                                .toInstant());
        when(mockTlsCert.getNotAfter()).thenReturn(expiry);
        when(eventProbe.counterMetric(anyString())).thenReturn(eventProbe);

        LocalDate expiryWindow =
                LocalDate.now().atStartOfDay(ZoneId.systemDefault()).plusWeeks(3).toLocalDate();

        certExpiryReminderHandler.handleRequest(null, context);

        Map<String, String> certExpiryMap = new HashMap<String, String>();
        certExpiryMap.put(
                "tlsCert",
                expiry.toInstant().atZone(ZoneId.systemDefault()).toLocalDate().toString());

        verify(eventProbe).addDimensions(certExpiryMap);
    }

    @Test
    void HandlerShouldNotIncrementMetricCountWhenCertIsOutsideExpiryWindow() {
        when(mockTlsCert.getNotAfter())
                .thenReturn(
                        Date.from(
                                LocalDate.now()
                                        .atStartOfDay(ZoneId.systemDefault())
                                        .plusWeeks(5)
                                        .toInstant()));

        certExpiryReminderHandler.handleRequest(null, context);

        verifyNoInteractions(eventProbe);
    }

    private void createCertificateMocks() {
        when(mockTlsRootCert.getNotAfter())
                .thenReturn(
                        Date.from(
                                LocalDate.now()
                                        .atStartOfDay(ZoneId.systemDefault())
                                        .plusWeeks(5)
                                        .toInstant()));
        when(mockTlsIntermediateCert.getNotAfter())
                .thenReturn(
                        Date.from(
                                LocalDate.now()
                                        .atStartOfDay(ZoneId.systemDefault())
                                        .plusWeeks(5)
                                        .toInstant()));
        when(mockTlsCert.getNotAfter())
                .thenReturn(
                        Date.from(
                                LocalDate.now()
                                        .atStartOfDay(ZoneId.systemDefault())
                                        .plusWeeks(5)
                                        .toInstant()));
    }
}
