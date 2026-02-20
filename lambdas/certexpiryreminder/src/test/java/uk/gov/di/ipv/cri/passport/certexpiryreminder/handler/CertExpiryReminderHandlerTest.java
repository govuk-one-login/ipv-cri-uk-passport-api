package uk.gov.di.ipv.cri.passport.certexpiryreminder.handler;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.certexpiryreminder.handler.config.CertExpiryReminderConfig;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.CERTIFICATE_EXPIRYS;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.CERTIFICATE_EXPIRY_REMINDER;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CERT_EXPIRY_REMINDER_COMPLETED_OK;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class CertExpiryReminderHandlerTest {
    @SystemStub private EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Mock private ParameterStoreService parameterStoreService;
    @Mock private CertExpiryReminderConfig certExpiryReminderConfig;
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

        when(certExpiryReminderConfig.getHMPOCertificates())
                .thenReturn(
                        Map.of(
                                "tlsCert", mockTlsCert,
                                "intermediate", mockTlsIntermediateCert,
                                "tlsRoot", mockTlsRootCert));

        environmentVariables.set("POWERTOOLS_METRICS_NAMESPACE", "StackName");

        // Use below certificate as control for tests
        this.certExpiryReminderHandler =
                new CertExpiryReminderHandler(
                        parameterStoreService, certExpiryReminderConfig, eventProbe);
    }

    @Test
    void HandlerShouldIncrementOkMetricCountWhenCompletedSuccessfully() {
        when(mockTlsCert.getNotAfter())
                .thenReturn(
                        Date.from(
                                LocalDate.now()
                                        .atStartOfDay(ZoneId.systemDefault())
                                        .plusWeeks(5)
                                        .toInstant()));

        certExpiryReminderHandler.handleRequest(null, context);

        InOrder inOrder = inOrder(eventProbe);
        inOrder.verify(eventProbe).counterMetric(LAMBDA_CERT_EXPIRY_REMINDER_COMPLETED_OK);
        inOrder.verifyNoMoreInteractions();
        verifyNoMoreInteractions(eventProbe);
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

        certExpiryReminderHandler.handleRequest(null, context);

        Map<String, String> certExpiryMap = new HashMap<String, String>();
        certExpiryMap.put(
                "tlsCert",
                expiry.toInstant().atZone(ZoneId.systemDefault()).toLocalDate().toString());

        InOrder inOrder = inOrder(eventProbe);
        inOrder.verify(eventProbe).counterMetric(CERTIFICATE_EXPIRY_REMINDER);
        inOrder.verify(eventProbe).counterMetric(CERTIFICATE_EXPIRYS);
        inOrder.verify(eventProbe).addDimensions(certExpiryMap);
        inOrder.verify(eventProbe).counterMetric(LAMBDA_CERT_EXPIRY_REMINDER_COMPLETED_OK);
        inOrder.verifyNoMoreInteractions();
        verifyNoMoreInteractions(eventProbe);
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
