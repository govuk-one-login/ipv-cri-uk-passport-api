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
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.ThirdPartyAPIResult;
import uk.gov.di.ipv.cri.passport.checkpassport.exception.OAuthHttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.cri.passport.checkpassport.validation.ValidationResult;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.helpers.PersonIdentityDetailedHelperMapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.cri.passport.library.domain.CheckType.DOCUMENT_DATA_VERIFICATION;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.DOCUMENT_DATA_VERIFICATION_REQUEST_FAILED;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.DOCUMENT_DATA_VERIFICATION_REQUEST_SUCCEEDED;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.FORM_DATA_VALIDATION_FAIL;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.FORM_DATA_VALIDATION_PASS;

public class DocumentDataVerificationService {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final int MAX_PASSPORT_GPG45_STRENGTH_VALUE = 4;
    private static final int MAX_PASSPORT_GPG45_VALIDITY_VALUE = 2;
    private static final int MIN_PASSPORT_GPG45_VALUE = 0;

    private final EventProbe eventProbe;
    private final AuditService auditService;

    private final FormDataValidator formDataValidator;
    private final ThirdPartyAPIService thirdPartyAPIService;

    public DocumentDataVerificationService(
            EventProbe eventProbe,
            AuditService auditService,
            ThirdPartyAPIService thirdPartyAPIService,
            FormDataValidator formDataValidator) {

        this.eventProbe = eventProbe;
        this.auditService = auditService;

        this.thirdPartyAPIService = thirdPartyAPIService;
        this.formDataValidator = formDataValidator;
    }

    public DocumentDataVerificationResult verifyData(
            PassportFormData passportFormData,
            SessionItem sessionItem,
            Map<String, String> requestHeaders)
            throws OAuthHttpResponseExceptionWithErrorBody {
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
                throw new OAuthHttpResponseExceptionWithErrorBody(
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        ErrorResponse.FORM_DATA_FAILED_VALIDATION);
            }
            LOGGER.info("Form data validated");
            eventProbe.counterMetric(FORM_DATA_VALIDATION_PASS);

            ThirdPartyAPIResult thirdPartyAPIResult =
                    thirdPartyAPIService.performCheck(passportFormData);

            LOGGER.info("Sending audit event REQUEST_SENT...");
            auditService.sendAuditEvent(
                    AuditEventType.REQUEST_SENT,
                    new AuditEventContext(
                            PersonIdentityDetailedHelperMapper
                                    .passportFormDataToAuditRestrictedFormat(passportFormData),
                            requestHeaders,
                            sessionItem));

            LOGGER.info("Third party response mapped");

            int documentStrengthScore = MAX_PASSPORT_GPG45_STRENGTH_VALUE;
            int documentValidityScore = calculateValidity(thirdPartyAPIResult);

            LOGGER.info("Mapping contra indicators from Third party response");
            List<String> cis = calculateContraIndicators(thirdPartyAPIResult);

            LOGGER.info("Generating Document Data Verification Result");
            DocumentDataVerificationResult documentDataVerificationResult =
                    new DocumentDataVerificationResult();

            documentDataVerificationResult.setContraIndicators(cis);

            documentDataVerificationResult.setStrengthScore(documentStrengthScore);
            documentDataVerificationResult.setValidityScore(documentValidityScore);

            documentDataVerificationResult.setTransactionId(thirdPartyAPIResult.getTransactionId());
            documentDataVerificationResult.setVerified(thirdPartyAPIResult.isValid());

            // These are captured but ignored during
            // evidence creation until requested
            // to be enabled
            List<String> checksSucceeded = new ArrayList<>();
            List<String> checksFailed = new ArrayList<>();
            if (documentDataVerificationResult.isVerified()) {
                checksSucceeded.add(DOCUMENT_DATA_VERIFICATION.toString());
            } else {
                checksFailed.add(DOCUMENT_DATA_VERIFICATION.toString());
            }
            documentDataVerificationResult.setChecksSucceeded(checksSucceeded);
            documentDataVerificationResult.setChecksFailed(checksFailed);

            // TODO Update and Check Audit Event with Extension if necessary
            auditService.sendAuditEvent(
                    AuditEventType.RESPONSE_RECEIVED,
                    new AuditEventContext(requestHeaders, sessionItem),
                    null);

            LOGGER.info(
                    "Document Data Verification Request Completed Indicators {}, Strength Score {}, Validity Score {}",
                    (cis != null) ? String.join(", ", cis.toString()) : "[]",
                    documentStrengthScore,
                    documentValidityScore);

            LOGGER.info("Third party transaction id {}", thirdPartyAPIResult.getTransactionId());

            // Verification Request Completed
            eventProbe.counterMetric(DOCUMENT_DATA_VERIFICATION_REQUEST_SUCCEEDED);

            return documentDataVerificationResult;
        } catch (OAuthHttpResponseExceptionWithErrorBody e) {
            eventProbe.counterMetric(DOCUMENT_DATA_VERIFICATION_REQUEST_FAILED);
            // Specific exception for all non-recoverable DCS related errors
            throw e;
        } catch (SqsException e) {
            // Audit Events are not working
            eventProbe
                    .log(
                            Level.ERROR,
                            ErrorResponse.FAILED_TO_SEND_AUDIT_MESSAGE_TO_SQS_QUEUE.getMessage())
                    .counterMetric(DOCUMENT_DATA_VERIFICATION_REQUEST_FAILED);
            throw new OAuthHttpResponseExceptionWithErrorBody(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_SEND_AUDIT_MESSAGE_TO_SQS_QUEUE);
        }
    }

    private int calculateValidity(ThirdPartyAPIResult thirdPartyAPIResult) {
        return thirdPartyAPIResult.isValid()
                ? MAX_PASSPORT_GPG45_VALIDITY_VALUE
                : MIN_PASSPORT_GPG45_VALUE;
    }

    private List<String> calculateContraIndicators(ThirdPartyAPIResult thirdPartyAPIResult) {
        return thirdPartyAPIResult.isValid() ? null : List.of("D02");
    }
}
