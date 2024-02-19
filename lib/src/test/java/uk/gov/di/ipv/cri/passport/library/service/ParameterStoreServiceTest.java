package uk.gov.di.ipv.cri.passport.library.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class ParameterStoreServiceTest {

    private static final String TEST_PARAM_NAME = "TEST-Parameter";
    private static final String TEST_PARAM_VALUE = "TEST-Parameter-Value";

    @SystemStub private EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Mock private ClientFactoryService mockClientFactoryService;
    @Mock SSMProvider mockSSMProvider;

    private final String AWS_STACK_NAME = "passport-api-dev";
    private final String PARAMETER_PREFIX = "passport-api-pipeline";
    private final String COMMON_PARAMETER_NAME_PREFIX = "commmon-lambdas";

    private ParameterStoreService parameterStoreService;

    @BeforeEach
    void setUp() {
        environmentVariables.set("AWS_REGION", "eu-west-2");
        environmentVariables.set("PARAMETER_PREFIX", PARAMETER_PREFIX);
        environmentVariables.set("AWS_STACK_NAME", AWS_STACK_NAME);
        environmentVariables.set("COMMON_PARAMETER_NAME_PREFIX", COMMON_PARAMETER_NAME_PREFIX);

        when(mockClientFactoryService.getSSMProvider()).thenReturn(mockSSMProvider);

        parameterStoreService = new ParameterStoreService(mockClientFactoryService);
    }

    @Test
    void shouldGetParamValueByParameterName() {
        String fullParamName = String.format("/%s/%s", PARAMETER_PREFIX, TEST_PARAM_NAME);
        when(mockSSMProvider.get(fullParamName)).thenReturn(TEST_PARAM_VALUE);
        assertEquals(TEST_PARAM_VALUE, parameterStoreService.getParameterValue(TEST_PARAM_NAME));
        verify(mockSSMProvider).get(fullParamName);
    }

    @Test
    void shouldGetEncryptedParameterValueByParameterName() {
        String fullParamName = String.format("/%s/%s", PARAMETER_PREFIX, TEST_PARAM_NAME);
        when(mockSSMProvider.withDecryption()).thenReturn(mockSSMProvider);
        when(mockSSMProvider.get(fullParamName)).thenReturn(TEST_PARAM_VALUE);
        assertEquals(
                TEST_PARAM_VALUE,
                parameterStoreService.getEncryptedParameterValue(TEST_PARAM_NAME));
        verify(mockSSMProvider).get(fullParamName);
    }

    @Test
    void shouldGetStackParameterValueValueByParameterName() {
        String fullParamName = String.format("/%s/%s", AWS_STACK_NAME, TEST_PARAM_NAME);
        when(mockSSMProvider.get(fullParamName)).thenReturn(TEST_PARAM_VALUE);
        assertEquals(
                TEST_PARAM_VALUE, parameterStoreService.getStackParameterValue(TEST_PARAM_NAME));
        verify(mockSSMProvider).get(fullParamName);
    }

    @Test
    void shouldCetCommonParameterValueValueByParameterName() {
        String fullParamName =
                String.format("/%s/%s", COMMON_PARAMETER_NAME_PREFIX, TEST_PARAM_NAME);
        when(mockSSMProvider.get(fullParamName)).thenReturn(TEST_PARAM_VALUE);
        assertEquals(
                TEST_PARAM_VALUE, parameterStoreService.getCommonParameterValue(TEST_PARAM_NAME));
        verify(mockSSMProvider).get(fullParamName);
    }
}
