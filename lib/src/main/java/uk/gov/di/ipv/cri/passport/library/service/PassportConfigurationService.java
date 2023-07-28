package uk.gov.di.ipv.cri.passport.library.service;

import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;

import java.time.temporal.ChronoUnit;
import java.util.Optional;

public final class PassportConfigurationService extends ConfigurationService {
    private static final String PARAMETER_NAME_FORMAT = "/%s/%s";
    private final String parameterPrefix;
    private final SSMProvider ssmProvider;

    // Note - Do not add to this class
    // TODO Delete this class once withDecryption
    //  is added to ConfigurationService in CRI-LIB.

    @ExcludeFromGeneratedCoverageReport
    public PassportConfigurationService(ClientFactoryService clientFactoryService) {
        this(
                ParamManager.getSsmProvider(clientFactoryService.getSsmClient())
                        .defaultMaxAge(getCacheTTLInMinutes(), ChronoUnit.MINUTES),
                Optional.ofNullable(System.getenv("PARAMETER_PREFIX"))
                        .orElse(System.getenv("AWS_STACK_NAME")));
    }

    public PassportConfigurationService(SSMProvider ssmProvider, String parameterPrefix) {
        this.ssmProvider = ssmProvider;
        this.parameterPrefix = parameterPrefix;
    }

    // Todo move to CRI-Lib
    public String getEncryptedSsmParameter(String parameterName) {
        return ssmProvider
                .withDecryption()
                .get(String.format(PARAMETER_NAME_FORMAT, parameterPrefix, parameterName));
    }

    // Borrowed From CRI-LIB
    // Todo delete when getEncryptedSsmParameter is moved
    private static int getCacheTTLInMinutes() {
        return Optional.ofNullable(System.getenv(CONFIG_SERVICE_CACHE_TTL_MINS))
                .map(Integer::valueOf)
                .orElse(5);
    }

    // Borrowed From CRI-LIB to allow parameterPrefix override
    // Todo delete when PARAMETER_PREFIX is added to ConfigurationService constructor
    @Override
    public String getParameterValue(String parameterName) {
        return ssmProvider.get(
                String.format(PARAMETER_NAME_FORMAT, parameterPrefix, parameterName));
    }
}
