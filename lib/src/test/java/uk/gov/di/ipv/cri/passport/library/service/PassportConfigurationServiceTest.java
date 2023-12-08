package uk.gov.di.ipv.cri.passport.library.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import uk.gov.di.ipv.cri.passport.library.helpers.KeyCertHelper;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_PASSPORT_CRI_ENCRYPTION_KEY;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_HTTPCLIENT_TLS_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_HTTPCLIENT_TLS_INTER_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_HTTPCLIENT_TLS_ROOT_CERT;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class PassportConfigurationServiceTest {

    public static final String TEST_PRIVATE_KEY =
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMUiC17ZaXozJZBH5N2Vsqdy+b8Vq1q043cZi9BxL4BAL9gkdqFI9HCiOxskqKQXE96jt/u6h4d1EECfrpM/pwVBXVnM8iKukUP62+SsrPdG+jgP+QVB6xTJkYuKV9nd1akgdVjiHQOnx3v03+OInhdhmTP7ob9nvUuLHFtM6xRKRFooGrELRnOpJRV4GsAWXjCHPyOzHNv2Ipk08v9VZfEIlCjHnHPC+pVSF5E4p2dOp0OKsKRQBFG5al9f4BP5y1Qw2z1mJgJV1w5QElGNgNACFKAR959b7rk1JxqPVaFwWe7T/XL+xFD0VrZNEUrozNl48sRXtiwxJU/yDj3J91AgMBAAECggEBALgss8WqQ5uuhNzO+xcrfU0bIHQ+LBkkMJ4zrI1/ye58l0Fy5PLPU5OipSgxYZWchfpcoIN0YdktHH86i80YiIAmm4PxFJlk+rLA79lfS8+S0msdBcFQwlXpiPtKvgosefKBPVE2jG5JuharAB/PUSJFtaoQwK8iEN9gGQbxA3uvmeWWQvxjPuC0/C/Bm2Tm+x5UrvfflqNRXXL3X/QkhU1ZHH/577w3Meua/wPcWVc7kUWhD3pMZDGM//uyYRQezC5oDKMtYAyN/YyiuF4oB3h8wiNtI54/px/caIJWzVk+zg1hqVTByG/MRWYqKIFVhzd58HfUi4vSB/1WR+PLoqECgYEA9PwZGTqqC2Mn9A3gHW882Go+rN/Owc+cOk4Z/C4ho9uh5v2EqaKPMDZkAY1E+FFThQej8ojrVIxoUK9gSQgpa+qOobDsgGrWVSqiP8u0L4M+Xn3Fg5MGquJ0voZ8t6CbdC+u7CV/RgtUnspGm3JgsARO8pOT4LCmwxzbdmDG+ikCgYEA1YH3cOmbd39cVMGE9YGYQF1ujEttkzCKOnfZHbUeOPSnx7FypKOMFaMig9NebsSzzyE2MtIDnm04D8ddnYtIA/y1Lho11rweo9SZ6hfSWU+xENABj9lY54hvQtuWmm9Hqi/BRdRaXncJOX9iQm252I1st+yiE2hM43YmcV2+vG0CgYAWfvfHC04GEarfjE6iJU7PCKKMuViBD5FnATj9oTbRlx982JbQBO9lG/l+8vv8WWtz8cmqQcxqTSJfFlufGTLEiBtk2Zw+BpF77JhNh2UaX9DgWGhEtsGL+5OA01SsgAEGYEKNyLuxMOUqV6S4LX6Xay3ctJSFs3L8w6+bZTOgUQKBgDWlgVnyqKie7MEzGshhNrM9hrBjp3WrZaAJSxmGz8A54QpxEMBDg8hQBDUhYAHvFMr/qlGcqWIeSU7VpjUWsRKnZZLe7RY2kHBT1BSYxbbBKllyGmJdl1Qd2O7wo+fL/DLL6wEzuT0xJbU3x6WvUloSNvYD1DmSJHem0UP87RcFAoGAS3Ucq788OvYge2a06J+SShSBWgG6cuMUwU+NUmsfAqjWQTDSdG63Atrb6jXC/r2gtZuuZSIXukRfKY1pLTrNpOaNfb/S8RWXIR/x6x88GZoMn00u9S+j+c3vzlRfJO2aOiOuClxDta+npCSK4NNna5BuJa/Cr7UewRm4U8D8oWM=";
    public static final String TEST_CERT =
            "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUgvVENDQmVXZ0F3SUJBZ0lRYUJZRTMvTTA4WEhZQ25OVm1jRkJjakFOQmdrcWhraUc5dzBCQVFzRkFEQnkKTVFzd0NRWURWUVFHRXdKVlV6RU9NQXdHQTFVRUNBd0ZWR1Y0WVhNeEVEQU9CZ05WQkFjTUIwaHZkWE4wYjI0eApFVEFQQmdOVkJBb01DRk5UVENCRGIzSndNUzR3TEFZRFZRUUREQ1ZUVTB3dVkyOXRJRVZXSUZOVFRDQkpiblJsCmNtMWxaR2xoZEdVZ1EwRWdVbE5CSUZJek1CNFhEVEl3TURRd01UQXdOVGd6TTFvWERUSXhNRGN4TmpBd05UZ3oKTTFvd2diMHhDekFKQmdOVkJBWVRBbFZUTVE0d0RBWURWUVFJREFWVVpYaGhjekVRTUE0R0ExVUVCd3dIU0c5MQpjM1J2YmpFUk1BOEdBMVVFQ2d3SVUxTk1JRU52Y25BeEZqQVVCZ05WQkFVVERVNVdNakF3T0RFMk1UUXlORE14CkZEQVNCZ05WQkFNTUMzZDNkeTV6YzJ3dVkyOXRNUjB3R3dZRFZRUVBEQlJRY21sMllYUmxJRTl5WjJGdWFYcGgKZEdsdmJqRVhNQlVHQ3lzR0FRUUJnamM4QWdFQ0RBWk9aWFpoWkdFeEV6QVJCZ3NyQmdFRUFZSTNQQUlCQXhNQwpWVk13Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRREhoZVJrYmIxRkNjN3hSS3N0CndLMEpJR2FLWTh0N0piUzJiUTJiNllJSkRnbkh1SVlIcUJyQ1VWNzlvZWxpa2tva1JrRnZjdnBhS2luRkhEUUgKVXBXRUk2UlVFUlltU0NnM084V2k0MnVPY1YyQjVaYWJtWENrd2R4WTVFY2w1MUJiTThVbkdkb0FHYmRObWlSbQpTbVRqY3MrbGhNeGc0ZkZZNmxCcGlFVkZpR1VqR1JSKzYxUjY3THo2VTRLSmVMTmNDbTA3UXdGWUtCbXBpMDhnCmR5Z1N2UmRVdzU1Sm9wcmVkaitWR3RqVWtCNGhGVDRHUVgvZ2h0NjlSbHF6Lys4dTBkRVFraHVVdXVjcnFhbG0KU0d5NDNIUndCZkRLRndZZVdNN0NQTWQ1ZS9kTyt0MDh0OFBianpWVFR2NWhRRENzRVlJVjJUN0FGSTlTY054TQpraDcvQWdNQkFBR2pnZ05CTUlJRFBUQWZCZ05WSFNNRUdEQVdnQlMvd1ZxSC95ajZRVDM5dDAva0hhK2dZVmdwCnZUQi9CZ2dyQmdFRkJRY0JBUVJ6TUhFd1RRWUlLd1lCQlFVSE1BS0dRV2gwZEhBNkx5OTNkM2N1YzNOc0xtTnYKYlM5eVpYQnZjMmwwYjNKNUwxTlRUR052YlMxVGRXSkRRUzFGVmkxVFUwd3RVbE5CTFRRd09UWXRVak11WTNKMApNQ0FHQ0NzR0FRVUZCekFCaGhSb2RIUndPaTh2YjJOemNITXVjM05zTG1OdmJUQWZCZ05WSFJFRUdEQVdnZ3QzCmQzY3VjM05zTG1OdmJZSUhjM05zTG1OdmJUQmZCZ05WSFNBRVdEQldNQWNHQldlQkRBRUJNQTBHQ3lxRWFBR0cKOW5jQ0JRRUJNRHdHRENzR0FRUUJncWt3QVFNQkJEQXNNQ29HQ0NzR0FRVUZCd0lCRmg1b2RIUndjem92TDNkMwpkeTV6YzJ3dVkyOXRMM0psY0c5emFYUnZjbmt3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdJR0NDc0dBUVVGCkJ3TUJNRWdHQTFVZEh3UkJNRDh3UGFBN29EbUdOMmgwZEhBNkx5OWpjbXh6TG5OemJDNWpiMjB2VTFOTVkyOXQKTFZOMVlrTkJMVVZXTFZOVFRDMVNVMEV0TkRBNU5pMVNNeTVqY213d0hRWURWUjBPQkJZRUZBREFGVUlhenc1cgpaSUhhcG5SeElVbnB3K0dMTUE0R0ExVWREd0VCL3dRRUF3SUZvRENDQVgwR0Npc0dBUVFCMW5rQ0JBSUVnZ0Z0CkJJSUJhUUZuQUhjQTlseVVMOUYzTUNJVVZCZ0lNSlJXanVOTkV4a3p2OThNTHlBTHpFN3haT01BQUFGeE0waG8KYndBQUJBTUFTREJHQWlFQTZ4ZWxpTlI4R2svNjNwWWRuUy92T3gvQ2pwdEVNRXY4OVdXaDEvdXJXSUVDSVFEeQpCcmVIVTI1RHp3dWtRYVJRandXNjU1WkxrcUNueGJ4UVdSaU9lbWo5SkFCMUFKUWd2QjZPMVkxc2lITWZnb3NpCkxBM1IyazFlYkUrVVBXSGJUaTlZVGFMQ0FBQUJjVE5JYU53QUFBUURBRVl3UkFJZ0dSRTR3emFiTlJkRDhrcS8KdkZQM3RRZTJobTB4NW5YdWxvd2g0SWJ3M2xrQ0lGWWIvM2xTRHBsUzdBY1I0citYcFd0RUtTVEZXSm1OQ1JiYwpYSnVyMlJHQkFIVUE3c0NWN28xeVpBK1M0OE81RzhjU28ybHFDWHRMYWhvVU9PWkhzc3Z0eGZrQUFBRnhNMGhvCjh3QUFCQU1BUmpCRUFpQjZJdmJvV3NzM1I0SXRWd2plYmw3RDN5b0ZhWDBORGgyZFdoaGd3Q3hySHdJZ0NmcTcKb2NNQzV0KzFqaTVNNXhhTG1QQzRJK1dYM0kvQVJrV1N5aU83SVFjd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dJQgpBQ2V1dXI0UW51anFtZ3VTckhVM21oZitjSm9kelRRTnFvNHRkZStQRDEvZUZkWUFFTHU4eEYrMEF0N3hKaVBZCmk1Ukt3aWx5UDU2diszaVkyVDlsdzdTOFRKMDQxVkxoYUlLcDE0TXpTVXpSeWVvT0FzSjdRQURNQ2xIS1VEbEgKVVUycE51bzg4WTZpZ292VDNic253Sk5pRVFOcXltU1NZaGt0dzB0YWR1b3FqcVhuMDZnc1Zpb1dUVkRYeXNkNQpxRXg0dDZzSWdJY01tMjZZSDF2SnBDUUVoS3BjMnkwN2dSa2tsQlpSdE1qVGh2NGNYeXlNWDd1VGNkVDdBSkJQCnVlaWZDb1YyNUp4WHVvOGQ1MTM5Z3dQMUJBZTdJQlZQeDJ1N0tOL1V5T1hkWm13TWYvVG1GR3dEZENmc3lIZi8KWnNCMndMSG96VFlvQVZtUTlGb1UxSkxnY1ZpdnFKK3ZObEJoSFhobHhNZE4wajgwUjlOejZFSWdsUWplSzNPOApJL2NGR20vQjgrNDJoT2xDSWQ5WmR0bmRKY1JKVmppMHdEMHF3ZXZDYWZBOWpKbEh2L2pzRStJOVV6NmNwQ3loCnN3K2xyRmR4VWdxVTU4YXhxZUs4OUZSK05vNHEwSUlPK0ppMXJKS3I5bmtTQjBCcVhvelZuRTFZQi9LTHZkSXMKdVlaSnVxYjJwS2t1K3p6VDZnVXdIVVRadkJpTk90WEw0Tnh3Yy9LVDdXek9TZDJ3UDEwUUk4REtnNHZmaU5EcwpIV21CMWM0S2ppNmdPZ0E1dVNVemFHbXEvdjRWbmNLNVVyK245TGJmbmZMYzI4SjVmdC9Hb3Rpbk15RGszaWFyCkYxMFlscWNPbWVYMXVGbUtiZGkvWG9yR2xrQ29NRjNURHg4cm1wOURCaUIvCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0";
    private static final String TEST_PARAM_NAME = "TEST-Parameter";
    private static final String TEST_PARAM_VALUE = "TEST-Parameter-Value";

    @SystemStub private EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Mock private ClientFactoryService mockClientFactoryService;
    @Mock SSMProvider mockSSMProvider;

    private final String AWS_STACK_NAME = "passport-api-dev";
    private final String PARAMETER_PREFIX = AWS_STACK_NAME;

    private PassportConfigurationService passportConfigurationService;

    @BeforeEach
    void setUp() {
        environmentVariables.set("AWS_REGION", "eu-west-2");
        environmentVariables.set("PARAMETER_PREFIX", PARAMETER_PREFIX);
        environmentVariables.set("AWS_STACK_NAME", AWS_STACK_NAME);

        passportConfigurationService =
                new PassportConfigurationService(mockSSMProvider, PARAMETER_PREFIX, AWS_STACK_NAME);
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

    @Test
    void shouldGetHMPOCertificatesFromParameterStore() throws CertificateException {

        String tlsCertParameterPath =
                String.format("/%s/%s", AWS_STACK_NAME, HMPO_HTTPCLIENT_TLS_CERT);
        String tlsIntermediateCertParameterPath =
                String.format("/%s/%s", AWS_STACK_NAME, HMPO_HTTPCLIENT_TLS_INTER_CERT);
        String tlsRootCertParameterPath =
                String.format("/%s/%s", AWS_STACK_NAME, HMPO_HTTPCLIENT_TLS_ROOT_CERT);

        when(mockSSMProvider.get(tlsCertParameterPath)).thenReturn(TEST_CERT);
        when(mockSSMProvider.get(tlsIntermediateCertParameterPath)).thenReturn(TEST_CERT);
        when(mockSSMProvider.get(tlsRootCertParameterPath)).thenReturn(TEST_CERT);

        X509Certificate tlsCertExpiry =
                (X509Certificate) KeyCertHelper.getDecodedX509Certificate(TEST_CERT);
        X509Certificate tlsIntermediateCertExpiry =
                (X509Certificate) KeyCertHelper.getDecodedX509Certificate(TEST_CERT);
        X509Certificate tlsRootCertExpiry =
                (X509Certificate) KeyCertHelper.getDecodedX509Certificate(TEST_CERT);

        Map<String, X509Certificate> hmpoCertMap = new HashMap<>();
        hmpoCertMap.put(HMPO_HTTPCLIENT_TLS_CERT, tlsCertExpiry);
        hmpoCertMap.put(HMPO_HTTPCLIENT_TLS_INTER_CERT, tlsIntermediateCertExpiry);
        hmpoCertMap.put(HMPO_HTTPCLIENT_TLS_ROOT_CERT, tlsRootCertExpiry);

        assertEquals(passportConfigurationService.getHMPOCertificates(), hmpoCertMap);

        assertEquals(
                passportConfigurationService.getParameterValue(HMPO_HTTPCLIENT_TLS_CERT),
                TEST_CERT);
        assertEquals(
                passportConfigurationService.getParameterValue(HMPO_HTTPCLIENT_TLS_INTER_CERT),
                TEST_CERT);
        assertEquals(
                passportConfigurationService.getParameterValue(HMPO_HTTPCLIENT_TLS_ROOT_CERT),
                TEST_CERT);
    }

    @Test
    void shouldGetParamValueByName() {
        String fullParamName = String.format("/%s/%s", AWS_STACK_NAME, TEST_PARAM_NAME);
        when(mockSSMProvider.get(fullParamName)).thenReturn(TEST_PARAM_VALUE);
        assertEquals(
                TEST_PARAM_VALUE, passportConfigurationService.getParameterValue(TEST_PARAM_NAME));
        verify(mockSSMProvider).get(fullParamName);
    }
}
