package uk.gov.di.ipv.cri.passport.certexpiryreminder.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.CorrelationIdPathConstants;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.service.ClientFactoryService;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.CERTIFICATE_EXPIRYS;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.CERTIFICATE_EXPIRY_REMINDER;

public class CertExpiryReminderHandler implements RequestHandler<Object, Object> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PassportConfigurationService passportConfigurationService;
    private final EventProbe eventProbe;

    @ExcludeFromGeneratedCoverageReport
    public CertExpiryReminderHandler()
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        ClientFactoryService clientFactoryService = new ClientFactoryService();

        this.passportConfigurationService = new PassportConfigurationService(clientFactoryService);

        this.eventProbe = new EventProbe();
    }

    public CertExpiryReminderHandler(
            PassportConfigurationService passportConfigurationService, EventProbe eventProbe) {
        LOGGER.info("CONSTRUCTING...");
        this.passportConfigurationService = passportConfigurationService;
        this.eventProbe = eventProbe;
    }

    @Override
    @Metrics(captureColdStart = true)
    @Logging(correlationIdPath = CorrelationIdPathConstants.EVENT_BRIDGE)
    public Object handleRequest(Object input, Context context) {
        LOGGER.info("Handling requests");

        Map<String, LocalDate> certificates = new HashMap<String, LocalDate>();

        LOGGER.info("Loading Certificates...");
        try {
            for (Map.Entry<String, X509Certificate> certificate :
                    passportConfigurationService.getHMPOCertificates().entrySet()) {
                Date date = certificate.getValue().getNotAfter();
                certificates.put(certificate.getKey(), convertToLocalDate(date));
            }
        } catch (CertificateException e) {
            throw new RuntimeException(e.getMessage());
        }

        LOGGER.info("Setting expiry window");
        LocalDate expiryWindow = LocalDate.now().plusWeeks(4);
        Map<String, String> certExpiryMap = new HashMap<String, String>();

        for (Map.Entry<String, LocalDate> certificate : certificates.entrySet()) {
            LOGGER.info("Checking Certificates...");

            if (certificate.getValue().isAfter(LocalDate.now())
                    && certificate.getValue().isBefore(expiryWindow)) {
                certExpiryMap.put(certificate.getKey(), certificate.getValue().toString());
                LOGGER.warn(
                        "cert path - {}, expires - {}",
                        certificate.getKey(),
                        certificate.getValue());

                eventProbe.counterMetric(CERTIFICATE_EXPIRY_REMINDER);
                eventProbe.counterMetric(CERTIFICATE_EXPIRYS).addDimensions(certExpiryMap);

            } else {
                LOGGER.info(
                        "cert path - {}, expires - {}",
                        certificate.getKey(),
                        certificate.getValue());
            }
        }
        LOGGER.info("Returning expired Certificates...");
        return "";
    }

    public LocalDate convertToLocalDate(Date dateToConvert) {
        return dateToConvert.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
    }
}
