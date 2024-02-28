package uk.gov.di.ipv.cri.passport.library.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.parameters.SSMProvider;

import java.util.Optional;

public class ParameterStoreService {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String LOG_MESSAGE_FORMAT = "{} {}";

    private static final String PARAMETER_NAME_FORMAT = "/%s/%s";

    // Prefixes
    private final String parameterPrefix; // Parameters that can hava prefix override
    private final String stackParameterPrefix; // Parameters that must always be from the stack
    private final String commonParameterPrefix; // Parameters from common-api

    private final SSMProvider ssmProvider;

    public ParameterStoreService(ClientFactoryService clientFactoryService) {

        this.ssmProvider = clientFactoryService.getSSMProvider();

        this.parameterPrefix =
                Optional.ofNullable(System.getenv("PARAMETER_PREFIX"))
                        .orElse(System.getenv("AWS_STACK_NAME"));

        this.stackParameterPrefix = System.getenv("AWS_STACK_NAME");

        this.commonParameterPrefix = System.getenv("COMMON_PARAMETER_NAME_PREFIX");
    }

    public String getParameterValue(String parameterName) {

        String parameterPath = String.format(PARAMETER_NAME_FORMAT, parameterPrefix, parameterName);

        LOGGER.debug(LOG_MESSAGE_FORMAT, "getParameterValue", parameterPath);

        return ssmProvider.get(
                String.format(PARAMETER_NAME_FORMAT, parameterPrefix, parameterName));
    }

    public String getEncryptedParameterValue(String parameterName) {

        String encryptedParameterPath =
                String.format(PARAMETER_NAME_FORMAT, parameterPrefix, parameterName);

        LOGGER.debug(LOG_MESSAGE_FORMAT, "getEncryptedParameterValue", encryptedParameterPath);

        return ssmProvider
                .withDecryption()
                .get(String.format(PARAMETER_NAME_FORMAT, parameterPrefix, parameterName));
    }

    public String getStackParameterValue(String parameterName) {

        String stackParameterPath =
                String.format(PARAMETER_NAME_FORMAT, stackParameterPrefix, parameterName);

        LOGGER.debug(LOG_MESSAGE_FORMAT, "getStackParameterValue", stackParameterPath);

        return ssmProvider.get(
                String.format(PARAMETER_NAME_FORMAT, stackParameterPrefix, parameterName));
    }

    public String getCommonParameterValue(String parameterName) {

        String commonParameterPath =
                String.format(PARAMETER_NAME_FORMAT, commonParameterPrefix, parameterName);

        LOGGER.debug(LOG_MESSAGE_FORMAT, "getCommonParameterValue", commonParameterPath);

        return ssmProvider.get(
                String.format(PARAMETER_NAME_FORMAT, commonParameterPrefix, parameterName));
    }
}