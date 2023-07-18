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
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_PASSPORT_CRI_ENCRYPTION_KEY;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class PassportConfigurationServiceTest {

    public static final String TEST_PRIVATE_KEY =
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMUiC17ZaXozJZBH5N2Vsqdy+b8Vq1q043cZi9BxL4BAL9gkdqFI9HCiOxskqKQXE96jt/u6h4d1EECfrpM/pwVBXVnM8iKukUP62+SsrPdG+jgP+QVB6xTJkYuKV9nd1akgdVjiHQOnx3v03+OInhdhmTP7ob9nvUuLHFtM6xRKRFooGrELRnOpJRV4GsAWXjCHPyOzHNv2Ipk08v9VZfEIlCjHnHPC+pVSF5E4p2dOp0OKsKRQBFG5al9f4BP5y1Qw2z1mJgJV1w5QElGNgNACFKAR959b7rk1JxqPVaFwWe7T/XL+xFD0VrZNEUrozNl48sRXtiwxJU/yDj3J91AgMBAAECggEBALgss8WqQ5uuhNzO+xcrfU0bIHQ+LBkkMJ4zrI1/ye58l0Fy5PLPU5OipSgxYZWchfpcoIN0YdktHH86i80YiIAmm4PxFJlk+rLA79lfS8+S0msdBcFQwlXpiPtKvgosefKBPVE2jG5JuharAB/PUSJFtaoQwK8iEN9gGQbxA3uvmeWWQvxjPuC0/C/Bm2Tm+x5UrvfflqNRXXL3X/QkhU1ZHH/577w3Meua/wPcWVc7kUWhD3pMZDGM//uyYRQezC5oDKMtYAyN/YyiuF4oB3h8wiNtI54/px/caIJWzVk+zg1hqVTByG/MRWYqKIFVhzd58HfUi4vSB/1WR+PLoqECgYEA9PwZGTqqC2Mn9A3gHW882Go+rN/Owc+cOk4Z/C4ho9uh5v2EqaKPMDZkAY1E+FFThQej8ojrVIxoUK9gSQgpa+qOobDsgGrWVSqiP8u0L4M+Xn3Fg5MGquJ0voZ8t6CbdC+u7CV/RgtUnspGm3JgsARO8pOT4LCmwxzbdmDG+ikCgYEA1YH3cOmbd39cVMGE9YGYQF1ujEttkzCKOnfZHbUeOPSnx7FypKOMFaMig9NebsSzzyE2MtIDnm04D8ddnYtIA/y1Lho11rweo9SZ6hfSWU+xENABj9lY54hvQtuWmm9Hqi/BRdRaXncJOX9iQm252I1st+yiE2hM43YmcV2+vG0CgYAWfvfHC04GEarfjE6iJU7PCKKMuViBD5FnATj9oTbRlx982JbQBO9lG/l+8vv8WWtz8cmqQcxqTSJfFlufGTLEiBtk2Zw+BpF77JhNh2UaX9DgWGhEtsGL+5OA01SsgAEGYEKNyLuxMOUqV6S4LX6Xay3ctJSFs3L8w6+bZTOgUQKBgDWlgVnyqKie7MEzGshhNrM9hrBjp3WrZaAJSxmGz8A54QpxEMBDg8hQBDUhYAHvFMr/qlGcqWIeSU7VpjUWsRKnZZLe7RY2kHBT1BSYxbbBKllyGmJdl1Qd2O7wo+fL/DLL6wEzuT0xJbU3x6WvUloSNvYD1DmSJHem0UP87RcFAoGAS3Ucq788OvYge2a06J+SShSBWgG6cuMUwU+NUmsfAqjWQTDSdG63Atrb6jXC/r2gtZuuZSIXukRfKY1pLTrNpOaNfb/S8RWXIR/x6x88GZoMn00u9S+j+c3vzlRfJO2aOiOuClxDta+npCSK4NNna5BuJa/Cr7UewRm4U8D8oWM=";

    @SystemStub private EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Mock private ClientFactoryService mockClientFactoryService;
    @Mock SSMProvider mockSSMProvider;

    private final String AWS_STACK_NAME = "passport-api-dev";

    private PassportConfigurationService passportConfigurationService;

    @BeforeEach
    void setUp() {
        environmentVariables.set("AWS_REGION", "eu-west-2");
        environmentVariables.set("AWS_STACK_NAME", AWS_STACK_NAME);

        passportConfigurationService =
                new PassportConfigurationService(mockSSMProvider, AWS_STACK_NAME);
    }

    @Test
    void shouldLoadPrivateKeyFromParameterStore() {

        when(mockSSMProvider.withDecryption()).thenReturn(mockSSMProvider);

        String parameterPath =
                String.format("/%s/%s", AWS_STACK_NAME, DCS_PASSPORT_CRI_ENCRYPTION_KEY);

        when(mockSSMProvider.get(parameterPath)).thenReturn(TEST_PRIVATE_KEY);

        String privateKey =
                passportConfigurationService.getEncryptedSsmParameter(
                        DCS_PASSPORT_CRI_ENCRYPTION_KEY);

        assertEquals(TEST_PRIVATE_KEY, privateKey);
    }
}
