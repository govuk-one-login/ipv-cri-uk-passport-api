package uk.gov.di.ipv.cri.passport.acceptance_tests.service;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConfigurationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigurationService.class);

    private final String publicApiBaseUrl;
    private final String coreStubEndpoint;
    private final String coreStubUsername;
    private final String coreStubPassword;
    private final String orchestratorStubUrl;
    private final String privateApiGatewayId;
    private final String environment;
    private final String publicApiGatewayId;
    private final String publicApiGatewayKey;
    private final boolean usingLocalStub;

    public ConfigurationService(String env) {

        if (StringUtils.isBlank(env)) {
            throw new IllegalArgumentException("env must be specified");
        }

        this.publicApiBaseUrl = getParameter("apiBaseUrl");
        this.coreStubEndpoint = getParameter("coreStubUrl");
        this.coreStubUsername = getParameter("coreStubUsername");
        this.coreStubPassword = getParameter("coreStubPassword");
        this.orchestratorStubUrl = getParameter("orchestratorStubUrl");
        this.privateApiGatewayId = getParameter("API_GATEWAY_ID_PRIVATE");
        this.publicApiGatewayId = getParameter("API_GATEWAY_ID_PUBLIC");
        this.publicApiGatewayKey = getParameter("API_GATEWAY_KEY");
        this.environment = env;
        this.usingLocalStub = getParameter("LOCAL") != null && getParameter("LOCAL").equals("yes");
    }

    private String getParameter(String paramName) {
        return System.getenv(paramName);
    }

    public String getPublicApiBaseUrl() {
        return publicApiBaseUrl;
    }

    public String getCoreStubEndpoint() {
        return coreStubEndpoint;
    }

    public String getCoreStubUsername() {
        return coreStubUsername;
    }

    public String getCoreStubPassword() {
        return coreStubPassword;
    }

    public String getPublicApiGatewayKey() {
        return publicApiGatewayKey;
    }

    public String getCoreStubUrl(boolean withAuth) {
        if (usingLocalStub) {
            return "http://" + coreStubEndpoint;
        } else {
            if (null != coreStubUsername && null != coreStubPassword && withAuth) {
                return "https://"
                        + coreStubUsername
                        + ":"
                        + coreStubPassword
                        + "@"
                        + coreStubEndpoint;
            } else {
                return "https://" + coreStubEndpoint;
            }
        }
    }

    public String getOrchestratorStubUrl() {
        if (usingLocalStub) {
            return "http://" + this.orchestratorStubUrl;
        } else {
            return "https://" + this.orchestratorStubUrl;
        }
    }

    public String getPrivateAPIEndpoint() {
        String privateGatewayId = this.privateApiGatewayId;
        if (privateGatewayId == null) {
            throw new IllegalArgumentException(
                    "Environment variable PRIVATE API endpoint is not set");
        }
        String stage =
                this.environment.equals("local") || this.environment.equals("shared-dev")
                        ? "dev"
                        : this.environment;
        LOGGER.info("privateGatewayId => {}", privateGatewayId);
        return "https://" + privateGatewayId + ".execute-api.eu-west-2.amazonaws.com/" + stage;
    }

    public String getPassportCRITestEnvironment() {
        String passportCRITestEnvironment = this.environment;
        if (passportCRITestEnvironment == null) {
            throw new IllegalArgumentException("Environment variable ENVIRONMENT is not set");
        }
        return passportCRITestEnvironment;
    }

    public String getPublicAPIEndpoint() {
        String publicGatewayId = this.publicApiGatewayId;
        if (publicGatewayId == null) {
            throw new IllegalArgumentException(
                    "Environment variable PUBLIC API endpoint is not set");
        }
        String stage =
                this.environment.equals("local") || this.environment.equals("shared-dev")
                        ? "dev"
                        : this.environment;
        LOGGER.info("publicGatewayId => {}", publicGatewayId);
        return "https://" + publicGatewayId + ".execute-api.eu-west-2.amazonaws.com/" + stage;
    }

    public boolean isUsingLocalStub() {
        return usingLocalStub;
    }
}
