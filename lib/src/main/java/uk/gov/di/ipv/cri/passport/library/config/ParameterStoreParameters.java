package uk.gov.di.ipv.cri.passport.library.config;

import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

public class ParameterStoreParameters {

    public static final String CONTRAINDICATION_MAPPINGS = "ContraindicationMappings";

    public static final String DOCUMENT_CHECK_RESULT_TABLE_NAME = "DocumentCheckResultTableName";
    public static final String DOCUMENT_CHECK_RESULT_TTL_PARAMETER =
            "SessionTtl"; // Linked to Common SessionTTL

    public static final String MAXIMUM_ATTEMPT_COUNT = "MaximumAttemptCount"; // Max Form Attempts

    public static final String IS_DCS_PERFORMANCE_STUB =
            "isDCSPerformanceStub"; // Always false unless using stubs
    public static final String IS_DVAD_PERFORMANCE_STUB =
            "isDVADPerformanceStub"; // Always false unless using stubs

    public static final String DVA_DIGITAL_ENABLED = "DvaDigitalEnabled";

    public static final String LOG_DCS_RESPONSE = "logDcsResponse";

    public static final String DCS_POST_URL = "DCS/PostUrl";
    public static final String DCS_HTTPCLIENT_TLS_CERT = "DCS/HttpClient/TLSCert";
    public static final String DCS_HTTPCLIENT_TLS_KEY = "DCS/HttpClient/TLSKey";
    public static final String DCS_HTTPCLIENT_TLS_INTER_CERT =
            "DCS/HttpClient/TLSIntermediateCertificate";
    public static final String DCS_HTTPCLIENT_TLS_ROOT_CERT = "DCS/HttpClient/TLSRootCertificate";
    public static final String DCS_PASSPORT_CRI_SIGNING_CERT =
            "DCS/JWS/SigningCertForDcsToVerify"; // JWS SHA-1 Certificate Thumbprint (Header)
    public static final String DCS_PASSPORT_CRI_SIGNING_KEY =
            "DCS/JWS/SigningKeyForPassportToSign"; // JWS RSA Signing Key
    public static final String DCS_ENCRYPTION_CERT =
            "DCS/JWE/EncryptionCertForPassportToEncrypt"; // JWE (Public Key)
    public static final String DCS_SIGNING_CERT =
            "DCS/JWE/SigningCertForPassportToVerify"; // DCS JWS (Reply Signature)
    public static final String DCS_PASSPORT_CRI_ENCRYPTION_KEY =
            "DCS/JWE/EncryptionKeyForPassportToDecrypt"; // DCS JWE (Private Key Reply Decrypt)

    public static final String HMPO_GRAPHQL_QUERY_STRING =
            "HMPODVAD/API/GraphQl/QueryString"; // Non-public

    public static final String HMPO_API_ENDPOINT_URL = "HMPODVAD/API/EndpointUrl";
    public static final String HMPO_API_ENDPOINT_HEALTH = "HMPODVAD/API/HealthPath";
    public static final String HMPO_API_ENDPOINT_TOKEN = "HMPODVAD/API/TokenPath";
    public static final String HMPO_API_ENDPOINT_GRAPHQL = "HMPODVAD/API/GraphQLPath";

    public static final String HMPO_HTTPCLIENT_TLS_CERT = "HMPODVAD/HttpClient/TLSCert";
    public static final String HMPO_HTTPCLIENT_TLS_KEY = "HMPODVAD/HttpClient/TLSKey";
    public static final String HMPO_HTTPCLIENT_TLS_INTER_CERT =
            "HMPODVAD/HttpClient/TLSIntermediateCertificate";
    public static final String HMPO_HTTPCLIENT_TLS_ROOT_CERT =
            "HMPODVAD/HttpClient/TLSRootCertificate";

    public static final String HMPO_API_HEADER_API_KEY = "HMPODVAD/API/Header/ApiKey";
    public static final String HMPO_API_HEADER_USER_AGENT = "HMPODVAD/API/Header/UserAgent";

    public static final String HMPO_API_HEADER_CLIENT_ID = "HMPODVAD/API/Header/ClientId";
    public static final String HMPO_API_HEADER_SECRET = "HMPODVAD/API/Header/Secret";

    public static final String HMPO_API_HEADER_GRANT_TYPE = "HMPODVAD/API/Header/GrantType";
    public static final String HMPO_API_HEADER_AUDIENCE = "HMPODVAD/API/Header/Audience";

    public static final String MAX_JWT_TTL_UNIT = "JwtTtlUnit"; // Issue Cred VC TTL

    @ExcludeFromGeneratedCoverageReport
    private ParameterStoreParameters() {
        throw new IllegalStateException("Instantiation is not valid for this class.");
    }
}
