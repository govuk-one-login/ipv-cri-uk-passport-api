package uk.gov.di.ipv.cri.passport.library.config;

public class ParameterStoreParameters {

    public static final String DOCUMENT_CHECK_RESULT_TABLE_NAME = "DocumentCheckResultTableName";
    public static final String MAXIMUM_ATTEMPT_COUNT = "MaximumAttemptCount"; // Max Form Attempts
    public static final String DVA_DIGITAL_ENABLED = "DvaDigitalEnabled";
    public static final String DCS_POST_URL = "DCS/PostUrl";
    public static final String HTTPCLIENT_TLS_CERT = "DCS/HttpClient/TLSCert";
    public static final String HTTPCLIENT_TLS_KEY = "DCS/HttpClient/TLSKey";
    public static final String HTTPCLIENT_TLS_INTERMEDIATE_CERT =
            "DCS/HttpClient/TLSIntermediateCertificate";
    public static final String HTTPCLIENT_TLS_ROOT_CERT = "DCS/HttpClient/TLSRootCertificate";
    public static final String PASSPORT_CRI_SIGNING_CERT =
            "DCS/JWS/SigningCertForDcsToVerify"; // JWS SHA-1 Certificate Thumbprint (Header)
    public static final String PASSPORT_CRI_SIGNING_KEY =
            "DCS/JWS/SigningKeyForPassportToSign"; // JWS RSA Signing Key
    public static final String DCS_ENCRYPTION_CERT =
            "DCS/JWE/EncryptionCertForPassportToEncrypt"; // JWE (Public Key)
    public static final String DCS_SIGNING_CERT =
            "DCS/JWE/SigningCertForPassportToVerify"; // DCS JWS (Reply Signature)
    public static final String PASSPORT_CRI_ENCRYPTION_KEY =
            "DCS/JWE/EncryptionKeyForPassportToDecrypt"; // DCS JWE (Private Key Reply Decrypt)

    public static final String MAX_JWT_TTL_UNIT = "JwtTtlUnit"; // Issue Cred VC TTL

    private ParameterStoreParameters() {
        throw new IllegalStateException("Instantiation is not valid for this class.");
    }
}
