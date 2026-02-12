package uk.gov.di.ipv.cri.passport.checkpassport.services;

import org.apache.http.HttpStatus;
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
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.fields.ContraIndicatorMapperResult;
import uk.gov.di.ipv.cri.passport.checkpassport.validation.ValidationResult;
import uk.gov.di.ipv.cri.passport.library.PassportFormTestDataGenerator;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.domain.Strategy;
import uk.gov.di.ipv.cri.passport.library.domain.result.ThirdPartyAPIResult;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;
import uk.gov.di.ipv.cri.passport.library.service.ThirdPartyAPIService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.domain.result.fields.APIResultSource.DVAD;
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
        "true, false, 0", // Document verified, No flags present - zero CI's
        "false, false, 1", // Document not verified, No flags present - Main CI only
        "false, true, 1", // Document not verified, Flag present, Main CI only
        "true, true, 1", // Document verified, Flag present, Flag CI
    })
    void verifyIdentityShouldReturnResultWhenValidInputProvided(
            boolean documentVerified, boolean flagsPresent, int expectedNumberOfCIs)
            throws OAuthErrorResponseException, SqsException {
        SessionItem sessionItem = new SessionItem();
        sessionItem.setSessionId(UUID.randomUUID());

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();
        ThirdPartyAPIResult thirdPartyAPIResult = new ThirdPartyAPIResult();
        thirdPartyAPIResult.setApiResultSource(DVAD);
        thirdPartyAPIResult.setValid(documentVerified);
        thirdPartyAPIResult.setTransactionId("12345");
        thirdPartyAPIResult.setFlags(Map.of("testFlag", "true"));

        ContraIndicatorMapperResult contraIndicatorMapperResult;
        if (flagsPresent) {
            // Simulate mapping the TestFlag flag to a CI
            contraIndicatorMapperResult =
                    ContraIndicatorMapperResult.builder()
                            .contraIndicators(new ArrayList<>(List.of("A01")))
                            .contraIndicatorReasons(new ArrayList<>(List.of("A01,testFlag")))
                            .contraIndicatorFailedChecks(new ArrayList<>(List.of("test_flag")))
                            .build();
        } else {
            contraIndicatorMapperResult = ContraIndicatorMapperResult.builder().build();
        }

        when(mockContraIndicatorMapper.mapFlagsToCIs(anyMap()))
                .thenReturn(contraIndicatorMapperResult);

        when(mockFormDataValidator.validate(passportFormData))
                .thenReturn(new ValidationResult<>(true, null));

        when(mocThirdPartyAPIService.performCheck(passportFormData, Strategy.NO_CHANGE))
                .thenReturn(thirdPartyAPIResult);

        DocumentDataVerificationResult documentDataVerificationResult =
                documentDataVerificationService.verifyData(
                        mocThirdPartyAPIService,
                        passportFormData,
                        sessionItem,
                        null,
                        Strategy.NO_CHANGE);

        InOrder inOrder = inOrder(mockEventProbe);
        inOrder.verify(mockEventProbe).counterMetric(FORM_DATA_VALIDATION_PASS);
        inOrder.verify(mockEventProbe).counterMetric(DOCUMENT_DATA_VERIFICATION_REQUEST_SUCCEEDED);
        verifyNoMoreInteractions(mockEventProbe);

        verify(mockFormDataValidator).validate(passportFormData);
        verify(mocThirdPartyAPIService).performCheck(passportFormData, Strategy.NO_CHANGE);

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
        assertEquals(
                !documentVerified || flagsPresent ? 0 : 2,
                documentDataVerificationResult.getValidityScore());
        assertEquals(
                expectedNumberOfCIs, documentDataVerificationResult.getContraIndicators().size());
        assertEquals(4, documentDataVerificationResult.getStrengthScore());

        if (documentVerified && !flagsPresent) {
            assertEquals(1, documentDataVerificationResult.getChecksSucceeded().size());
            assertTrue(
                    documentDataVerificationResult.getChecksSucceeded().contains("record_check"));

            assertEquals(0, documentDataVerificationResult.getChecksFailed().size());

        } else if (!documentVerified && !flagsPresent) {
            assertEquals(0, documentDataVerificationResult.getChecksSucceeded().size());

            assertEquals(1, documentDataVerificationResult.getChecksFailed().size());
            assertTrue(documentDataVerificationResult.getChecksFailed().contains("record_check"));
        } else if (documentVerified && flagsPresent) {
            assertEquals(1, documentDataVerificationResult.getChecksSucceeded().size());
            assertTrue(
                    documentDataVerificationResult.getChecksSucceeded().contains("record_check"));

            assertEquals(1, documentDataVerificationResult.getChecksFailed().size());
            assertTrue(documentDataVerificationResult.getChecksFailed().contains("test_flag"));

        } else { // (!documentVerified && flagsPresent)

            assertEquals(0, documentDataVerificationResult.getChecksSucceeded().size());

            // Main Check overrides all others
            assertEquals(1, documentDataVerificationResult.getChecksFailed().size());
            // Only the main flag should be present
            assertTrue(documentDataVerificationResult.getChecksFailed().contains("record_check"));
            assertFalse(documentDataVerificationResult.getChecksFailed().contains("test_flag"));
        }

        assertEquals(DVAD, documentDataVerificationResult.getApiResultSource());
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
                                    mocThirdPartyAPIService,
                                    passportFormData,
                                    sessionItem,
                                    null,
                                    Strategy.NO_CHANGE);
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
                .performCheck(passportFormData, Strategy.NO_CHANGE);

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () -> {
                            documentDataVerificationService.verifyData(
                                    mocThirdPartyAPIService,
                                    passportFormData,
                                    sessionItem,
                                    null,
                                    Strategy.NO_CHANGE);
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

        doThrow(exceptionCaught)
                .when(mockAuditService)
                .sendAuditEvent(eq(AuditEventType.REQUEST_SENT), any(AuditEventContext.class));

        OAuthErrorResponseException thrownException =
                assertThrows(
                        OAuthErrorResponseException.class,
                        () -> {
                            documentDataVerificationService.verifyData(
                                    mocThirdPartyAPIService,
                                    passportFormData,
                                    sessionItem,
                                    null,
                                    Strategy.NO_CHANGE);
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
