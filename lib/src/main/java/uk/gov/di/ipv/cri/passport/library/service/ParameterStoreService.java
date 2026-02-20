package uk.gov.di.ipv.cri.passport.library.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.lambda.powertools.parameters.ssm.SSMProvider;

import java.util.Map;
import java.util.Optional;

public class ParameterStoreService {

    private static final Logger LOGGER = LoggerFactory.getLogger(ParameterStoreService.class);
    private static final String LOG_MESSAGE_FORMAT = "{} {}";

    private static final String PARAMETER_NAME_FORMAT = "/%s/%s";

    // Prefixes
    private final String parameterPrefix; // Parameters that can hava prefix override
    private final String stackParameterPrefix; // Parameters that must always be from the stack

    private final SSMProvider ssmProvider;

    public ParameterStoreService(SSMProvider ssmProvider) {
        this.ssmProvider = ssmProvider;

        this.parameterPrefix =
                Optional.ofNullable(System.getenv("PARAMETER_PREFIX"))
                        .orElse(System.getenv("AWS_STACK_NAME"));

        this.stackParameterPrefix = System.getenv("AWS_STACK_NAME");
    }

    public String getParameterValue(String parameterName) {

        String parameterPath = String.format(PARAMETER_NAME_FORMAT, parameterPrefix, parameterName);

        LOGGER.debug(LOG_MESSAGE_FORMAT, "getParameterValue", parameterPath);

        return ssmProvider.get(parameterPath);
    }

    public String getEncryptedParameterValue(String parameterName) {

        String encryptedParameterPath =
                String.format(PARAMETER_NAME_FORMAT, parameterPrefix, parameterName);

        LOGGER.debug(LOG_MESSAGE_FORMAT, "getEncryptedParameterValue", encryptedParameterPath);

        return ssmProvider.withDecryption().get(encryptedParameterPath);
    }

    public String getStackParameterValue(String parameterName) {

        String stackParameterPath =
                String.format(PARAMETER_NAME_FORMAT, stackParameterPrefix, parameterName);

        LOGGER.debug(LOG_MESSAGE_FORMAT, "getStackParameterValue", stackParameterPath);

        return ssmProvider.get(stackParameterPath);
    }

    public Map<String, String> getAllParametersFromPath(String path) {

        String parametersPath = String.format(PARAMETER_NAME_FORMAT, parameterPrefix, path);

        LOGGER.debug(LOG_MESSAGE_FORMAT, "getAllParametersFromPath", parametersPath);

        return ssmProvider.recursive().getMultiple(parametersPath);
    }

    public Map<String, String> getAllParametersFromPathWithDecryption(String path) {

        String encryptedParametersPath =
                String.format(PARAMETER_NAME_FORMAT, parameterPrefix, path);

        LOGGER.debug(
                LOG_MESSAGE_FORMAT,
                "getAllParametersFromPathWithDecryption",
                encryptedParametersPath);

        return ssmProvider.withDecryption().getMultiple(encryptedParametersPath);
    }
}
