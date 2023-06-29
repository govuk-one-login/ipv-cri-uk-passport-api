package uk.gov.di.ipv.cri.passport.issuecredential.util;

import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.issuecredential.domain.audit.VCISSDocumentCheckAuditExtension;
import uk.gov.di.ipv.cri.passport.issuecredential.domain.verifiablecredential.Evidence;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;

import java.util.ArrayList;
import java.util.List;

public class IssueCredentialPassportAuditExtensionUtil {

    @ExcludeFromGeneratedCoverageReport
    private IssueCredentialPassportAuditExtensionUtil() {
        throw new IllegalStateException("Instantiation is not valid for this class.");
    }

    public static VCISSDocumentCheckAuditExtension generateVCISSDocumentCheckAuditExtension(
            String vcIssuer, List<DocumentCheckResultItem> documentCheckResultItems) {

        List<Evidence> evidenceList = new ArrayList<>();

        for (DocumentCheckResultItem documentCheckResultItem : documentCheckResultItems) {

            Evidence evidence =
                    EvidenceHelper.documentCheckResultItemToEvidence(documentCheckResultItem);

            evidenceList.add(evidence);
        }

        return new VCISSDocumentCheckAuditExtension(vcIssuer, evidenceList);
    }
}
