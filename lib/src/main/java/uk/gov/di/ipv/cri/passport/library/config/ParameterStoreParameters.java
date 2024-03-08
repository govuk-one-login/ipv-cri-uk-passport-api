package uk.gov.di.ipv.cri.passport.library.config;

import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

public class ParameterStoreParameters {

    public static final String CONTRAINDICATION_MAPPINGS = "ContraindicationMappings";

    public static final String DOCUMENT_CHECK_RESULT_TABLE_NAME = "DocumentCheckResultTableName";
    public static final String DOCUMENT_CHECK_RESULT_TTL_PARAMETER =
            "SessionTtl"; // Linked to Common SessionTTL

    public static final String HMPO_GRAPHQL_QUERY_STRING =
            "HMPODVAD/API/GraphQl/QueryString"; // Non-public

    public static final String HMPO_API_ENDPOINT_URL = "HMPODVAD/API/EndpointUrl";
    public static final String HMPO_API_ENDPOINT_HEALTH = "HMPODVAD/API/HealthPath";
    public static final String HMPO_API_ENDPOINT_TOKEN = "HMPODVAD/API/TokenPath";
    public static final String HMPO_API_ENDPOINT_GRAPHQL = "HMPODVAD/API/GraphQLPath";

    public static final String HMPO_API_HEADER_PARAMETER_PATH = "HMPODVAD/API/Header";

    public static final String HMPO_HTTP_CLIENT_PARAMETER_PATH = "HMPODVAD/HttpClient";

    public static final String MAX_JWT_TTL_UNIT = "JwtTtlUnit"; // Issue Cred VC TTL

    @ExcludeFromGeneratedCoverageReport
    private ParameterStoreParameters() {
        throw new IllegalStateException("Instantiation is not valid for this class.");
    }
}
