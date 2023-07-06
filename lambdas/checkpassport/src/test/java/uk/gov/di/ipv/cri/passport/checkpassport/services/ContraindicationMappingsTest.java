package uk.gov.di.ipv.cri.passport.checkpassport.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.CONTRAINDICATION_MAPPINGS;

@ExtendWith(SystemStubsExtension.class)
@ExtendWith(MockitoExtension.class)
class ContraindicationMappingsTest {

    // FLAG-NAME : MATCHING VALUE : ASSOCIATED CI
    private static final String SINGLE_MAPPING_FORMAT = "%s@%s:%s";

    // FLAG-NAME : MATCHING VALUE, FLAG-NAME : MATCHING VALUE : ASSOCIATED CI
    private static final String MULTI_MAPPING_FORMAT = "%s@%s,%s@%s:%s";

    private static final String MAPPING_CI_FLAG_1 =
            String.format(SINGLE_MAPPING_FORMAT, "FLAG1", true, "A01");
    private static final String MAPPING_CI_FLAG_2 =
            String.format(SINGLE_MAPPING_FORMAT, "FLAG2", false, "B02");
    private static final String MAPPING_CI_FLAG_3 =
            String.format(SINGLE_MAPPING_FORMAT, "FLAG3", true, "C03");
    private static final String MAPPING_CI_FLAG_4 =
            String.format(MULTI_MAPPING_FORMAT, "FLAG4", true, "FLAG5", false, "D04");

    private static final String CI_MAP =
            MAPPING_CI_FLAG_1
                    + "||"
                    + MAPPING_CI_FLAG_2
                    + "||"
                    + MAPPING_CI_FLAG_3
                    + "||"
                    + MAPPING_CI_FLAG_4;

    @SystemStub private EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Mock private ServiceFactory mockServiceFactory;

    @Mock private PassportConfigurationService mockPassportConfigurationService;

    private ContraIndicatorMapper contraIndicatorMapper;

    @BeforeEach
    void setUp() {
        environmentVariables.set("CIMap", CI_MAP);

        // Not all the test use this ContraIndicatorMapper, some setup up a new one for the purposes
        // of the test
        contraIndicatorMapper = new ContraIndicatorMapper(mockServiceFactory);
    }

    @Test
    void shouldCreateContraIndicatorMapperUsingCiMapFromEnvVar() {
        assertNotNull(contraIndicatorMapper);
    }

    @Test
    void shouldCreateContraIndicatorMapperUsingCiMapFromParameterStore() {
        // Clear the env var so ContraIndicatorMapper will use parameter store
        environmentVariables.set("CIMap", null);

        // Not used in this test as mapper setup via parameter store is being tested
        contraIndicatorMapper = null;

        when(mockServiceFactory.getPassportConfigurationService())
                .thenReturn(mockPassportConfigurationService);

        when(mockPassportConfigurationService.getParameterValue(CONTRAINDICATION_MAPPINGS))
                .thenReturn(CI_MAP);
        ContraIndicatorMapper testContraIndicatorMapper =
                new ContraIndicatorMapper(mockServiceFactory);

        verify(mockPassportConfigurationService, times(1))
                .getParameterValue(CONTRAINDICATION_MAPPINGS);
        assertNotNull(testContraIndicatorMapper);
    }

    @Test
    void shouldReturnCIForOneValidSingleMapping() {

        Map<String, String> testflagMap = new HashMap<>();
        testflagMap.put("FLAG1", "true");

        List<String> ciCodes = contraIndicatorMapper.mapFlagsToCIs(testflagMap);

        assertNotNull(ciCodes);
        assertEquals(1, ciCodes.size());
        assertEquals("A01", ciCodes.get(0));
    }

    @Test
    void shouldReturnCIForTwoValidSingleMappings() {
        Map<String, String> testflagMap = new HashMap<>();
        testflagMap.put("FLAG1", "true");
        testflagMap.put("FLAG2", "false");

        List<String> ciCodes = contraIndicatorMapper.mapFlagsToCIs(testflagMap);

        assertNotNull(ciCodes);
        assertEquals(2, ciCodes.size());

        assertTrue(ciCodes.contains("A01"));
        assertTrue(ciCodes.contains("B02"));
    }

    @Test
    void shouldReturnCIForFlagsInMultiMapping() {
        Map<String, String> testflagMap = new HashMap<>();
        testflagMap.put("FLAG4", "true");
        testflagMap.put("FLAG5", "false");

        List<String> ciCodes = contraIndicatorMapper.mapFlagsToCIs(testflagMap);

        assertNotNull(ciCodes);
        assertEquals(1, ciCodes.size());

        assertTrue(ciCodes.contains("D04"));
    }

    @Test
    void shouldReturnNoCIIfFlagValuesDoNotMatchMapping() {
        Map<String, String> testflagMap = new HashMap<>();
        testflagMap.put("FLAG4", "false"); // Mapping requires true
        testflagMap.put("FLAG5", "true"); // Mapping requires false

        List<String> ciCodes = contraIndicatorMapper.mapFlagsToCIs(testflagMap);

        assertNotNull(ciCodes);

        assertEquals(0, ciCodes.size());
    }

    @Test
    void shouldReturnNoCIIfNoFlagsProvided() {
        Map<String, String> testflagMap = new HashMap<>();

        List<String> ciCodes = contraIndicatorMapper.mapFlagsToCIs(testflagMap);

        assertNotNull(ciCodes);
        assertEquals(0, ciCodes.size());
    }

    @Test
    void shouldLogErrorIfUnmappedFlagsFound() {

        // Not used in this test, null to ensure accidental usage is spotted
        contraIndicatorMapper = null;

        // Mocks the logger creation and verifies the ERROR log line
        try (MockedStatic<LogManager> mockedLogManager = mockStatic(LogManager.class)) {
            Logger mockedStaticLogger = mock(Logger.class);
            mockedLogManager.when(LogManager::getLogger).thenReturn(mockedStaticLogger);

            Map<String, String> testflagMap = new HashMap<>();
            testflagMap.put("FLAG1", "false"); // Valid flag but not correct value
            testflagMap.put("UNMAPPED_FLAG1", "false");
            testflagMap.put("UNMAPPED_FLAG2", "true");

            // ContraIndicatorMapper just for this test (so log mocking is only here)
            ContraIndicatorMapper testContraIndicatorMapper =
                    new ContraIndicatorMapper(mockServiceFactory);

            List<String> ciCodes = testContraIndicatorMapper.mapFlagsToCIs(testflagMap);

            // Note mocking suppresses error log line output in test
            // also note Flags output order is reversed
            verify(mockedStaticLogger)
                    .error("Unmapped flags encountered: {}", "UNMAPPED_FLAG2, UNMAPPED_FLAG1");

            assertNotNull(ciCodes);
            assertEquals(0, ciCodes.size());
        }
    }
}
