package uk.gov.di.ipv.cri.passport.checkpassport.util;

import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.DocumentDataVerificationResult;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;

import java.util.UUID;

public class DocumentDataVerificationServiceResultDataGenerator {
    public static DocumentDataVerificationResult generate(PassportFormData data) {
        DocumentDataVerificationResult testDocumentDataVerificationResult =
                new DocumentDataVerificationResult();

        testDocumentDataVerificationResult.setTransactionId(UUID.randomUUID().toString());
        testDocumentDataVerificationResult.setVerified(true);

        testDocumentDataVerificationResult.setContraIndicators(null);
        testDocumentDataVerificationResult.setStrengthScore(4);
        testDocumentDataVerificationResult.setValidityScore(1);

        return testDocumentDataVerificationResult;
    }
}
