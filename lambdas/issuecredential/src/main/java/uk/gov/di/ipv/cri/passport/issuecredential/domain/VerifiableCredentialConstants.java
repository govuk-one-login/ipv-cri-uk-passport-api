package uk.gov.di.ipv.cri.passport.issuecredential.domain;

import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

public class VerifiableCredentialConstants {
    public static final String VC_CLAIM_KEY = "vc";
    public static final String VC_CLAIM_TYPE_KEY = "type";
    public static final String VC_CREDENTIAL_TYPE_VC =
            "VerifiableCredential"; // Internally added by VerifiableCredentialClaimsSetBuilder CANARY
    public static final String VC_CREDENTIAL_TYPE_ICC = "IdentityCheckCredential";
    public static final String VC_SUBJECT_KEY = "credentialSubject";
    public static final String VC_NAME_KEY = "name";
    public static final String VC_BIRTHDATE_KEY = "birthDate";
    public static final String VC_PASSPORT_KEY = "passport";
    public static final String VC_EVIDENCE_KEY = "evidence";

    @ExcludeFromGeneratedCoverageReport
    private VerifiableCredentialConstants() {
        throw new IllegalStateException("Instantiation is not valid for this class.");
    }
}
