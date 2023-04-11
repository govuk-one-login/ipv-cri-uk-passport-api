package uk.gov.di.ipv.cri.passport.issuecredential.util;

import uk.gov.di.ipv.cri.passport.issuecredential.domain.checkdetails.Check;
import uk.gov.di.ipv.cri.passport.issuecredential.domain.verifiablecredential.Evidence;
import uk.gov.di.ipv.cri.passport.issuecredential.domain.verifiablecredential.EvidenceType;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;

import java.util.ArrayList;
import java.util.List;

public class EvidenceHelper {
    private EvidenceHelper() {
        throw new IllegalStateException("Instantiation is not valid for this class.");
    }

    public static Evidence documentCheckResultItemToEvidence(
            DocumentCheckResultItem documentCheckResultItem) {
        Evidence evidence = new Evidence();
        evidence.setType(String.valueOf(EvidenceType.IDENTITY_CHECK));
        evidence.setTxn(documentCheckResultItem.getTransactionId());

        evidence.setStrengthScore(documentCheckResultItem.getStrengthScore());
        evidence.setValidityScore(documentCheckResultItem.getValidityScore());

        evidence.setCi(documentCheckResultItem.getContraIndicators());

        List<String> stringCheckDetails = documentCheckResultItem.getCheckDetails();
        if (stringCheckDetails != null && !stringCheckDetails.isEmpty()) {
            evidence.setCheckDetails(createCheckList(stringCheckDetails, documentCheckResultItem));
        }

        List<String> stringFailedCheckDetails = documentCheckResultItem.getFailedCheckDetails();
        if (stringFailedCheckDetails != null && !stringFailedCheckDetails.isEmpty()) {
            evidence.setFailedCheckDetails(
                    createCheckList(stringFailedCheckDetails, documentCheckResultItem));
        }

        return evidence;
    }

    private static List<Check> createCheckList(
            List<String> stringChecks, DocumentCheckResultItem documentCheckResultItem) {

        List<Check> checkList = new ArrayList<>();

        for (String checkName : stringChecks) {

            // EnumValue to String lowercase (VC)
            Check check = new Check(checkName.toLowerCase());

            checkList.add(check);
        }

        return checkList;
    }
}
