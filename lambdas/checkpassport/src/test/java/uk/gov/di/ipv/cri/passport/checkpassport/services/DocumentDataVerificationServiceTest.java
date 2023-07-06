package uk.gov.di.ipv.cri.passport.checkpassport.services;

import org.apache.http.HttpStatus;
import org.apache.logging.log4j.Level;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventContext;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventType;
import uk.gov.di.ipv.cri.common.library.exception.SqsException;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.DocumentDataVerificationResult;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.ThirdPartyAPIResult;
import uk.gov.di.ipv.cri.passport.checkpassport.validation.ValidationResult;
import uk.gov.di.ipv.cri.passport.library.PassportFormTestDataGenerator;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.DOCUMENT_DATA_VERIFICATION_REQUEST_FAILED;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.DOCUMENT_DATA_VERIFICATION_REQUEST_SUCCEEDED;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.FORM_DATA_VALIDATION_FAIL;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.FORM_DATA_VALIDATION_PASS;

@ExtendWith(MockitoExtension.class)
class DocumentDataVerificationServiceTest {

    @Mock private ServiceFactory mockServiceFactory;
    @Mock private EventProbe mockEventProbe;
    @Mock private AuditService mockAuditService;

    @Mock private FormDataValidator mockFormDataValidator;

    @Mock private ContraIndicatorMapper mockContraIndicatorMapper;
    @Mock private ThirdPartyAPIService mocThirdPartyAPIService;

    private DocumentDataVerificationService documentDataVerificationService;

    @BeforeEach
    void setUp() {
        mockServiceFactoryBehaviour();

        documentDataVerificationService =
                new DocumentDataVerificationService(
                        mockServiceFactory, mockFormDataValidator, mockContraIndicatorMapper);
    }

    @ParameterizedTest
    @CsvSource({
        "true", "false",
    })
    void verifyIdentityShouldReturnResultWhenValidInputProvided(boolean documentVerified)
            throws OAuthErrorResponseException, SqsException {
        SessionItem sessionItem = new SessionItem();
        sessionItem.setSessionId(UUID.randomUUID());

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();
        ThirdPartyAPIResult thirdPartyAPIResult = new ThirdPartyAPIResult();
        thirdPartyAPIResult.setValid(documentVerified);
        thirdPartyAPIResult.setTransactionId("12345");
        thirdPartyAPIResult.setFlags(Map.of("TestMap", "NotUsed"));

        when(mockFormDataValidator.validate(passportFormData))
                .thenReturn(new ValidationResult<>(true, null));

        when(mocThirdPartyAPIService.performCheck(passportFormData))
                .thenReturn(thirdPartyAPIResult);

        DocumentDataVerificationResult documentDataVerificationResult =
                documentDataVerificationService.verifyData(
                        mocThirdPartyAPIService, passportFormData, sessionItem, null);

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe).counterMetric(FORM_DATA_VALIDATION_PASS);
        inOrder.verify(mockEventProbe).counterMetric(DOCUMENT_DATA_VERIFICATION_REQUEST_SUCCEEDED);
        verifyNoMoreInteractions(mockEventProbe);

        verify(mockFormDataValidator).validate(passportFormData);
        verify(mocThirdPartyAPIService).performCheck(passportFormData);

        verify(mockAuditService)
                .sendAuditEvent(eq(AuditEventType.REQUEST_SENT), any(AuditEventContext.class));
        verify(mockAuditService)
                .sendAuditEvent(
                        eq(AuditEventType.RESPONSE_RECEIVED),
                        any(AuditEventContext.class),
                        eq(null));
        verifyNoMoreInteractions(mockAuditService);

        assertNotNull(documentDataVerificationResult);
        assertEquals(documentVerified, documentDataVerificationResult.isVerified());
        assertEquals(documentVerified ? 2 : 0, documentDataVerificationResult.getValidityScore());
        assertEquals(
                documentVerified ? 0 : 1,
                documentDataVerificationResult.getContraIndicators().size());
        assertEquals(4, documentDataVerificationResult.getStrengthScore());
    }

    @Test
    void verifyIdentityShouldReturnValidationErrorWhenInvalidInputProvided() {
        SessionItem sessionItem = new SessionItem();
        sessionItem.setSessionId(UUID.randomUUID());

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();

        when(mockFormDataValidator.validate(passportFormData))
                .thenReturn(new ValidationResult<>(false, List.of("validation error")));

        OAuthErrorResponseException expectedReturnedException =
                new OAuthErrorResponseException(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.FORM_DATA_FAILED_VALIDATION);

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () -> {
                            documentDataVerificationService.verifyData(
                                    mocThirdPartyAPIService, passportFormData, sessionItem, null);
                        });

        assertEquals(expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        assertEquals(expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
        verify(mockEventProbe).counterMetric(FORM_DATA_VALIDATION_FAIL);
        verify(mockEventProbe).counterMetric(DOCUMENT_DATA_VERIFICATION_REQUEST_FAILED);
        verifyNoMoreInteractions(mockEventProbe);
        verifyNoInteractions(mockAuditService);
    }

    @Test
    void verifyIdentityShouldReturnErrorWhenThirdPartyCallFails()
            throws OAuthErrorResponseException {
        SessionItem sessionItem = new SessionItem();
        sessionItem.setSessionId(UUID.randomUUID());

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();

        when(mockFormDataValidator.validate(passportFormData))
                .thenReturn(new ValidationResult<>(true, null));

        OAuthErrorResponseException expectedReturnedException =
                new OAuthErrorResponseException(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.ERROR_INVOKING_LEGACY_THIRD_PARTY_API);

        doThrow(expectedReturnedException)
                .when(mocThirdPartyAPIService)
                .performCheck(passportFormData);

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () -> {
                            documentDataVerificationService.verifyData(
                                    mocThirdPartyAPIService, passportFormData, sessionItem, null);
                        });

        assertEquals(expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        assertEquals(expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
        verify(mockEventProbe).counterMetric(FORM_DATA_VALIDATION_PASS);
        verify(mockEventProbe).counterMetric(DOCUMENT_DATA_VERIFICATION_REQUEST_FAILED);
        verifyNoMoreInteractions(mockEventProbe);
        verifyNoInteractions(mockAuditService);
    }

    @Test
    void verifyIdentityShouldReturnErrorWhenAuditServiceFailsToSend() throws SqsException {
        SessionItem sessionItem = new SessionItem();
        sessionItem.setSessionId(UUID.randomUUID());

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();

        when(mockFormDataValidator.validate(passportFormData))
                .thenReturn(new ValidationResult<>(true, null));

        SqsException exceptionCaught = new SqsException("Sqs Send fail");

        OAuthErrorResponseException expectedReturnedException =
                new OAuthErrorResponseException(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_SEND_AUDIT_MESSAGE_TO_SQS_QUEUE);

        when(mockEventProbe.log(
                        any(Level.class),
                        eq(ErrorResponse.FAILED_TO_SEND_AUDIT_MESSAGE_TO_SQS_QUEUE.getMessage())))
                .thenReturn(mockEventProbe);

        doThrow(exceptionCaught)
                .when(mockAuditService)
                .sendAuditEvent(eq(AuditEventType.REQUEST_SENT), any(AuditEventContext.class));

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () -> {
                            documentDataVerificationService.verifyData(
                                    mocThirdPartyAPIService, passportFormData, sessionItem, null);
                        });

        assertEquals(expectedReturnedException.getStatusCode(), thrownException.getStatusCode());
        assertEquals(expectedReturnedException.getErrorReason(), thrownException.getErrorReason());
        verify(mockEventProbe).counterMetric(FORM_DATA_VALIDATION_PASS);
        verify(mockEventProbe).counterMetric(DOCUMENT_DATA_VERIFICATION_REQUEST_FAILED);
        verifyNoMoreInteractions(mockEventProbe);
        verifyNoMoreInteractions(mockAuditService);
    }

    private void mockServiceFactoryBehaviour() {
        when(mockServiceFactory.getEventProbe()).thenReturn(mockEventProbe);
        when(mockServiceFactory.getAuditService()).thenReturn(mockAuditService);
    }
}
