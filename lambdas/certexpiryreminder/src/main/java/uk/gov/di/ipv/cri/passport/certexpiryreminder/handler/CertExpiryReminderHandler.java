package uk.gov.di.ipv.cri.passport.certexpiryreminder.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.lambda.powertools.logging.CorrelationIdPaths;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.FlushMetrics;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.common.library.util.ClientProviderFactory;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.certexpiryreminder.handler.config.CertExpiryReminderConfig;
import uk.gov.di.ipv.cri.passport.library.logging.LoggingSupport;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.CERTIFICATE_EXPIRYS;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.CERTIFICATE_EXPIRY_REMINDER;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CERT_EXPIRY_REMINDER_COMPLETED_ERROR;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.LAMBDA_CERT_EXPIRY_REMINDER_COMPLETED_OK;

public class CertExpiryReminderHandler implements RequestHandler<Object, Object> {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertExpiryReminderHandler.class);

    static {
        LoggingSupport.populateLambdaInitLoggerValues();
    }

    private final ParameterStoreService parameterStoreService;

    private final CertExpiryReminderConfig certExpiryReminderConfig;

    private final EventProbe eventProbe;

    @ExcludeFromGeneratedCoverageReport
    public CertExpiryReminderHandler() {
        // Note avoidExecutionInterceptorsOnClientsUsedByPowerTools being false is safe as long as
        // no
        // ssm secrets/parameters are read in the constructor
        ClientProviderFactory clientProviderFactory = new ClientProviderFactory(true, false);

        this.parameterStoreService =
                new ParameterStoreService(clientProviderFactory.getSSMProvider());

        this.certExpiryReminderConfig = new CertExpiryReminderConfig(parameterStoreService);

        this.eventProbe = new EventProbe();
    }

    public CertExpiryReminderHandler(
            ParameterStoreService parameterStoreService,
            CertExpiryReminderConfig certExpiryReminderConfig,
            EventProbe eventProbe) {
        LOGGER.info("CONSTRUCTING...");
        this.parameterStoreService = parameterStoreService;
        this.certExpiryReminderConfig = certExpiryReminderConfig;
        this.eventProbe = eventProbe;
    }

    @Override
    @FlushMetrics(captureColdStart = true)
    @Logging(clearState = true, correlationIdPath = CorrelationIdPaths.EVENT_BRIDGE)
    public Object handleRequest(Object input, Context context) {
        try {
            LOGGER.info("Handling requests");

            Map<String, LocalDate> certificates = new HashMap<>();

            LOGGER.info("Loading Certificates...");

            for (Map.Entry<String, X509Certificate> certificate :
                    certExpiryReminderConfig.getHMPOCertificates().entrySet()) {
                Date date = certificate.getValue().getNotAfter();
                certificates.put(certificate.getKey(), convertToLocalDate(date));
            }

            LOGGER.info("Setting expiry window");
            LocalDate expiryWindow = LocalDate.now().plusWeeks(4);
            Map<String, String> certExpiryMap = new HashMap<>();

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

            return lambdaCompletedOk();
        } catch (CertificateException e) {
            eventProbe.counterMetric(LAMBDA_CERT_EXPIRY_REMINDER_COMPLETED_ERROR);
            throw new RuntimeException(e.getMessage());
        }
    }

    private String lambdaCompletedOk() {
        // Lambda Complete No Error
        eventProbe.counterMetric(LAMBDA_CERT_EXPIRY_REMINDER_COMPLETED_OK);

        return "Success";
    }

    public LocalDate convertToLocalDate(Date dateToConvert) {
        return dateToConvert.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
    }
}
