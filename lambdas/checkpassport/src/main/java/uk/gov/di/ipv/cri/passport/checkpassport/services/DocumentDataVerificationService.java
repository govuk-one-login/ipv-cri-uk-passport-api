package uk.gov.di.ipv.cri.passport.checkpassport.services;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventContext;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventType;
import uk.gov.di.ipv.cri.common.library.exception.SqsException;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.DocumentDataVerificationResult;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.fields.ContraIndicatorMapperResult;
import uk.gov.di.ipv.cri.passport.checkpassport.validation.ValidationResult;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.domain.Strategy;
import uk.gov.di.ipv.cri.passport.library.domain.result.ThirdPartyAPIResult;
import uk.gov.di.ipv.cri.passport.library.domain.result.fields.APIResultSource;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;
import uk.gov.di.ipv.cri.passport.library.helpers.PersonIdentityDetailedHelperMapper;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;
import uk.gov.di.ipv.cri.passport.library.service.ThirdPartyAPIService;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.DOCUMENT_DATA_VERIFICATION_REQUEST_FAILED;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.DOCUMENT_DATA_VERIFICATION_REQUEST_SUCCEEDED;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.FORM_DATA_VALIDATION_FAIL;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.FORM_DATA_VALIDATION_PASS;

public class DocumentDataVerificationService {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final String DOCUMENT_DATA_VERIFICATION_CI = "D02";
    private static final String DOCUMENT_DATA_VERIFICATION_CHECK_NAME = "record_check";
    private static final String DOCUMENT_DATA_VERIFICATION_CI_REASON = "NoMatchingRecord";

    private static final int MAX_PASSPORT_GPG45_STRENGTH_VALUE = 4;
    private static final int MAX_PASSPORT_GPG45_VALIDITY_VALUE = 2;
    private static final int MIN_PASSPORT_GPG45_VALUE = 0;

    private final EventProbe eventProbe;
    private final AuditService auditService;

    private final FormDataValidator formDataValidator;
    private final ContraIndicatorMapper contraIndicatorMapper;

    public DocumentDataVerificationService(
            ServiceFactory serviceFactory,
            FormDataValidator formDataValidator,
            ContraIndicatorMapper contraIndicatorMapper) {

        this.eventProbe = serviceFactory.getEventProbe();
        this.auditService = serviceFactory.getAuditService();

        this.formDataValidator = formDataValidator;

        this.contraIndicatorMapper = contraIndicatorMapper;
    }

    public DocumentDataVerificationResult verifyData(
            ThirdPartyAPIService thirdPartyAPIService,
            PassportFormData passportFormData,
            SessionItem sessionItem,
            Map<String, String> requestHeaders,
            Strategy strategy)
            throws OAuthErrorResponseException {
        try {
            LOGGER.info("Validating form data...");
            ValidationResult<List<String>> validationResult =
                    this.formDataValidator.validate(passportFormData);
            if (!validationResult.isValid()) {
                String errorMessages = String.join(",", validationResult.getError());
                LOGGER.error(
                        "{} - {} ",
                        ErrorResponse.FORM_DATA_FAILED_VALIDATION.getMessage(),
                        errorMessages);
                eventProbe.counterMetric(FORM_DATA_VALIDATION_FAIL);
                throw new OAuthErrorResponseException(
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        ErrorResponse.FORM_DATA_FAILED_VALIDATION);
            }
            LOGGER.info("Form data validated");
            eventProbe.counterMetric(FORM_DATA_VALIDATION_PASS);

            LOGGER.info(
                    "Performing data verification using {}", thirdPartyAPIService.getServiceName());
            ThirdPartyAPIResult thirdPartyAPIResult =
                    thirdPartyAPIService.performCheck(passportFormData, strategy);

            LOGGER.info("Sending audit event {}...", AuditEventType.REQUEST_SENT);
            auditService.sendAuditEvent(
                    AuditEventType.REQUEST_SENT,
                    new AuditEventContext(
                            PersonIdentityDetailedHelperMapper
                                    .passportFormDataToAuditRestrictedFormat(passportFormData),
                            requestHeaders,
                            sessionItem));

            LOGGER.info("Third party response mapped");

            APIResultSource apiResultSource = thirdPartyAPIResult.getApiResultSource();

            LOGGER.info("Mapping contra-indicators from Third party response");
            ContraIndicatorMapperResult contraIndicatorMapperResult =
                    getContraIndicatorsResult(thirdPartyAPIResult);

            List<String> cis = contraIndicatorMapperResult.contraIndicators();
            int documentStrengthScore = MAX_PASSPORT_GPG45_STRENGTH_VALUE;
            int documentValidityScore = calculateValidity(thirdPartyAPIResult, cis);

            if (null != thirdPartyAPIResult.getFlags()) {
                LOGGER.info(
                        "Passport check performed successfully. Flags {}, CIs {}",
                        thirdPartyAPIResult.getFlags().keySet().stream()
                                .map(key -> key + "=" + thirdPartyAPIResult.getFlags().get(key))
                                .collect(Collectors.joining(", ", "{", "}")),
                        String.join(",", cis));
            } else {
                LOGGER.info("No flags returned on request to {}", apiResultSource);
            }

            LOGGER.info(
                    "Generating Document Data Verification Result from {} ThirdPartyAPIResult",
                    apiResultSource.getName());
            DocumentDataVerificationResult documentDataVerificationResult =
                    new DocumentDataVerificationResult();

            documentDataVerificationResult.setApiResultSource(apiResultSource);

            documentDataVerificationResult.setContraIndicators(cis);

            documentDataVerificationResult.setStrengthScore(documentStrengthScore);
            documentDataVerificationResult.setValidityScore(documentValidityScore);

            documentDataVerificationResult.setTransactionId(thirdPartyAPIResult.getTransactionId());
            documentDataVerificationResult.setVerified(thirdPartyAPIResult.isValid());

            // See ContraIndicatorMapperResult as CI Mapper handles CI, CIReasons and CIChecks
            documentDataVerificationResult.setChecksSucceeded(
                    contraIndicatorMapperResult.contraIndicatorChecks());
            documentDataVerificationResult.setChecksFailed(
                    contraIndicatorMapperResult.contraIndicatorFailedChecks());
            documentDataVerificationResult.setContraIndicatorReasons(
                    contraIndicatorMapperResult.contraIndicatorReasons());

            LOGGER.info("Sending audit event {}...", AuditEventType.RESPONSE_RECEIVED);
            auditService.sendAuditEvent(
                    AuditEventType.RESPONSE_RECEIVED,
                    new AuditEventContext(requestHeaders, sessionItem),
                    null);

            LOGGER.info(
                    "Document Data Verification Request Completed Indicators {}, Strength Score {}, Validity Score {}",
                    !cis.isEmpty() ? String.join(", ", cis.toString()) : "[]",
                    documentStrengthScore,
                    documentValidityScore);

            LOGGER.info("Third party transaction id {}", thirdPartyAPIResult.getTransactionId());

            // Verification Request Completed
            eventProbe.counterMetric(DOCUMENT_DATA_VERIFICATION_REQUEST_SUCCEEDED);

            return documentDataVerificationResult;
        } catch (OAuthErrorResponseException e) {
            eventProbe.counterMetric(DOCUMENT_DATA_VERIFICATION_REQUEST_FAILED);
            // Specific exception for all non-recoverable ThirdPartyAPI related errors
            throw e;
        } catch (SqsException e) {
            // Audit Events are not working
            eventProbe
                    .log(
                            Level.ERROR,
                            ErrorResponse.FAILED_TO_SEND_AUDIT_MESSAGE_TO_SQS_QUEUE.getMessage())
                    .counterMetric(DOCUMENT_DATA_VERIFICATION_REQUEST_FAILED);
            throw new OAuthErrorResponseException(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_SEND_AUDIT_MESSAGE_TO_SQS_QUEUE);
        }
    }

    private int calculateValidity(ThirdPartyAPIResult thirdPartyAPIResult, List<String> cis) {
        return (!thirdPartyAPIResult.isValid() || !cis.isEmpty())
                ? MIN_PASSPORT_GPG45_VALUE
                : MAX_PASSPORT_GPG45_VALIDITY_VALUE;
    }

    // Handles the special case processing for the DOCUMENT_DATA_VERIFICATION_CI
    private ContraIndicatorMapperResult getContraIndicatorsResult(
            ThirdPartyAPIResult thirdPartyAPIResult) {

        ContraIndicatorMapperResult contraIndicatorMapperResult;

        // should we not check failed first. Why do all this if were going to clear anyway
        // Legacy API will not set any flags
        if (thirdPartyAPIResult.getFlags() != null) {
            Map<String, String> flagMap = thirdPartyAPIResult.getFlags();

            for (Map.Entry<String, String> entry : flagMap.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();
                String message = String.format("Flag %s : Value %s", key, value);
                LOGGER.debug(message);
            }

            contraIndicatorMapperResult = contraIndicatorMapper.mapFlagsToCIs(flagMap);

            List<String> flagCIs = contraIndicatorMapperResult.contraIndicators();
            for (String ci : flagCIs) {
                String message = String.format("Flag CI's %s ", ci);
                LOGGER.debug(message);
            }

        } else {
            // To maintain legacy compatibility incase DCS needs was re-enabled
            contraIndicatorMapperResult = ContraIndicatorMapperResult.builder().build();
        }

        List<String> ciCodes = contraIndicatorMapperResult.contraIndicators();
        List<String> ciReason = contraIndicatorMapperResult.contraIndicatorReasons();

        List<String> ciChecks = contraIndicatorMapperResult.contraIndicatorChecks();
        List<String> ciFailedChecks = contraIndicatorMapperResult.contraIndicatorFailedChecks();

        // isValid to VERIFICATION mapping is not processed as a flag
        if (!thirdPartyAPIResult.isValid()) {

            // Ensure in this scenario that all other flags are ignored
            ciCodes.clear();
            ciReason.clear();
            ciChecks.clear();
            ciFailedChecks.clear();

            // CI's
            ciCodes.add(DOCUMENT_DATA_VERIFICATION_CI);

            // Verification CI Reason "CI,Reason"
            ciReason.add(
                    DOCUMENT_DATA_VERIFICATION_CI + "," + DOCUMENT_DATA_VERIFICATION_CI_REASON);

            ciFailedChecks.add(DOCUMENT_DATA_VERIFICATION_CHECK_NAME);
        } else {
            ciChecks.add(DOCUMENT_DATA_VERIFICATION_CHECK_NAME);
        }

        return contraIndicatorMapperResult;
    }
}
