package uk.gov.di.ipv.cri.passport.library;

import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

public class DocumentCheckTestDataGenerator {

    private DocumentCheckTestDataGenerator() {
        throw new IllegalStateException("Instantiation is not valid for this class.");
    }

    public static DocumentCheckResultItem generateVerifiedResultItem() {
        return generateVerifiedResultItem(
                UUID.randomUUID(), UUID.randomUUID().toString().substring(0, 8));
    }

    public static DocumentCheckResultItem generateUnverifiedResultItem() {
        return generateUnverifiedResultItem(
                UUID.randomUUID(), UUID.randomUUID().toString().substring(0, 8));
    }

    public static DocumentCheckResultItem generateVerifiedResultItem(
            UUID sessionId, String passportNumber) {
        LocalDate expiryDate = LocalDate.now().plusYears(5);

        DocumentCheckResultItem documentCheckResultItem = new DocumentCheckResultItem();

        documentCheckResultItem.setSessionId(sessionId);

        documentCheckResultItem.setDocumentNumber(passportNumber);
        documentCheckResultItem.setExpiryDate(expiryDate.toString());

        documentCheckResultItem.setContraIndicators(null); // No CI's

        documentCheckResultItem.setStrengthScore(4);
        documentCheckResultItem.setValidityScore(2);

        documentCheckResultItem.setTransactionId(UUID.randomUUID().toString());

        documentCheckResultItem.setCheckDetails(List.of("verification_check"));

        documentCheckResultItem.setCiReasons(null);

        return documentCheckResultItem;
    }

    public static DocumentCheckResultItem generateUnverifiedResultItem(
            UUID sessionId, String passportNumber) {
        LocalDate expiryDate = LocalDate.now().plusYears(5);

        DocumentCheckResultItem documentCheckResultItem = new DocumentCheckResultItem();

        documentCheckResultItem.setSessionId(sessionId);

        documentCheckResultItem.setDocumentNumber(passportNumber);
        documentCheckResultItem.setExpiryDate(expiryDate.toString());

        documentCheckResultItem.setContraIndicators(List.of("CI1"));

        documentCheckResultItem.setStrengthScore(4);
        documentCheckResultItem.setValidityScore(0);

        documentCheckResultItem.setTransactionId(UUID.randomUUID().toString());

        documentCheckResultItem.setFailedCheckDetails(List.of("verification_check"));

        documentCheckResultItem.setCiReasons(List.of("CI1,Verification"));

        return documentCheckResultItem;
    }
}
