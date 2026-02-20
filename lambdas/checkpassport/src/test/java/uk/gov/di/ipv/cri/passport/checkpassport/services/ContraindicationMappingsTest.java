package uk.gov.di.ipv.cri.passport.checkpassport.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.fields.ContraIndicatorMapperResult;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

    // FLAG-NAME : MATCHING VALUE > FLAG-NAME : MATCHING VALUE : ASSOCIATED CI
    // The last flag will be the reason that is overridden
    private static final String MULTI_MAPPING_FORMAT_CI_REASON_OVERRIDE = "%s@%s>%s@%s:%s";
    private static final String TRIPLE_MAPPING_FORMAT_CI_REASON_OVERRIDE = "%s@%s>%s@%s>%s@%s:%s";

    // flags must be camelCase
    private static final String MAPPING_CI_FLAG_1 =
            String.format(SINGLE_MAPPING_FORMAT, "flagOne", true, "A01");
    private static final String MAPPING_CI_FLAG_2 =
            String.format(SINGLE_MAPPING_FORMAT, "flagTwo", false, "B02");
    private static final String MAPPING_CI_FLAG_3 =
            String.format(SINGLE_MAPPING_FORMAT, "flagThree", true, "C03");
    private static final String MAPPING_CI_FLAG_4 =
            String.format(MULTI_MAPPING_FORMAT, "flagFive", false, "flagFour", true, "D04");
    private static final String MAPPING_CI_FLAG_5 =
            String.format("%s@%s,%s@%s:%s", "flagSeven", true, "flagSix", true, "E05");
    private static final String MAPPING_CI_FLAG_6 =
            String.format(
                    "%s@%s,%s@%s,%s@%s:%s",
                    "flagTen", true, "flagEight", true, "flagNine", true, "F06");

    // CI Map containing all the mappings above
    private static final String CI_MAP =
            MAPPING_CI_FLAG_1
                    + "||"
                    + MAPPING_CI_FLAG_2
                    + "||"
                    + MAPPING_CI_FLAG_3
                    + "||"
                    + MAPPING_CI_FLAG_4
                    + "||"
                    + MAPPING_CI_FLAG_5
                    + "||"
                    + MAPPING_CI_FLAG_6;

    @SystemStub private EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Mock private ServiceFactory mockServiceFactory;

    @Mock private ParameterStoreService mockParameterStoreService;

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

        when(mockServiceFactory.getParameterStoreService()).thenReturn(mockParameterStoreService);

        when(mockParameterStoreService.getParameterValue(CONTRAINDICATION_MAPPINGS))
                .thenReturn(CI_MAP);
        ContraIndicatorMapper testContraIndicatorMapper =
                new ContraIndicatorMapper(mockServiceFactory);

        verify(mockParameterStoreService, times(1)).getParameterValue(CONTRAINDICATION_MAPPINGS);
        assertNotNull(testContraIndicatorMapper);
    }

    @Test
    void shouldReturnCIForOneValidSingleMapping() {

        Map<String, String> testflagMap = new HashMap<>();
        testflagMap.put("flagOne", "true");

        ContraIndicatorMapperResult mapperResult = contraIndicatorMapper.mapFlagsToCIs(testflagMap);

        assertNotNull(mapperResult);

        assertNotNull(mapperResult.contraIndicators());
        assertNotNull(mapperResult.contraIndicatorReasons());
        assertNotNull(mapperResult.contraIndicatorChecks());
        assertNotNull(mapperResult.contraIndicatorFailedChecks());

        List<String> ciCodes = mapperResult.contraIndicators();
        List<String> ciReason = mapperResult.contraIndicatorReasons();
        List<String> ciChecks = mapperResult.contraIndicatorChecks();
        List<String> ciFailedChecks = mapperResult.contraIndicatorFailedChecks();

        assertNotNull(ciCodes);
        assertEquals(1, ciCodes.size());
        assertEquals("A01", ciCodes.get(0));

        assertEquals(1, ciReason.size());
        assertEquals("A01,One", ciReason.get(0));

        // No passed checks
        assertEquals(0, ciChecks.size());

        assertEquals(1, ciFailedChecks.size());
        assertEquals("one_check", ciFailedChecks.get(0));
    }

    @Test
    void shouldReturnCIForTwoValidSingleMappings() {
        Map<String, String> testflagMap = new HashMap<>();
        testflagMap.put("flagOne", "true");
        testflagMap.put("flagTwo", "false");

        ContraIndicatorMapperResult mapperResult = contraIndicatorMapper.mapFlagsToCIs(testflagMap);

        assertNotNull(mapperResult);

        assertNotNull(mapperResult.contraIndicators());
        assertNotNull(mapperResult.contraIndicatorReasons());
        assertNotNull(mapperResult.contraIndicatorChecks());
        assertNotNull(mapperResult.contraIndicatorFailedChecks());

        List<String> ciCodes = mapperResult.contraIndicators();
        List<String> ciReason = mapperResult.contraIndicatorReasons();
        List<String> ciChecks = mapperResult.contraIndicatorChecks();
        List<String> ciFailedChecks = mapperResult.contraIndicatorFailedChecks();

        assertNotNull(ciCodes);
        assertEquals(2, ciCodes.size());
        assertTrue(ciCodes.contains("A01"));
        assertTrue(ciCodes.contains("B02"));

        assertEquals(2, ciReason.size());

        assertTrue(ciReason.contains("A01,One"));
        assertTrue(ciReason.contains("B02,Two"));

        // No passed checks
        assertEquals(0, ciChecks.size());

        assertEquals(2, ciFailedChecks.size());
        assertTrue(ciFailedChecks.contains("one_check"));
        assertTrue(ciFailedChecks.contains("two_check"));
    }

    // Current implementation does not allow for multi reasons to one CI
    /*    @Test
    void shouldReturnSingleCIForFlagsInMultiMapping() {
        Map<String, String> testflagMap = new HashMap<>();
        testflagMap.put("flagFour", "true");
        testflagMap.put("flagFive", "false");

        ContraIndicatorMapperResult mapperResult = contraIndicatorMapper.mapFlagsToCIs(testflagMap);

        assertNotNull(mapperResult);

        assertNotNull(mapperResult.getContraIndicators());
        assertNotNull(mapperResult.getContraIndicatorReasons());
        assertNotNull(mapperResult.getContraIndicatorChecks());
        assertNotNull(mapperResult.getContraIndicatorFailedChecks());

        List<String> ciCodes = mapperResult.getContraIndicators();
        List<String> ciReason = mapperResult.getContraIndicatorReasons();
        List<String> ciChecks = mapperResult.getContraIndicatorChecks();
        List<String> ciFailedChecks = mapperResult.getContraIndicatorFailedChecks();

        assertNotNull(ciCodes);
        assertEquals(1, ciCodes.size());
        assertTrue(ciCodes.contains("D04"));

        assertEquals(2, ciReason.size());
        assertTrue(ciReason.contains("D04,Four"));
        assertTrue(ciReason.contains("D04,Five"));

        // No passed checks
        assertEquals(0, ciChecks.size());

        assertEquals(2, ciFailedChecks.size());
        assertTrue(ciFailedChecks.contains("four_check"));
        assertTrue(ciFailedChecks.contains("five_check"));
    }*/

    @Test
    void shouldReturnNoCIIfFlagValuesDoNotMatchMapping() {
        Map<String, String> testflagMap = new HashMap<>();
        testflagMap.put("flagFour", "false"); // Mapping requires true
        testflagMap.put("flagFive", "true"); // Mapping requires false

        ContraIndicatorMapperResult mapperResult = contraIndicatorMapper.mapFlagsToCIs(testflagMap);

        assertNotNull(mapperResult);

        assertNotNull(mapperResult.contraIndicators());
        assertNotNull(mapperResult.contraIndicatorReasons());
        assertNotNull(mapperResult.contraIndicatorChecks());
        assertNotNull(mapperResult.contraIndicatorFailedChecks());

        List<String> ciCodes = mapperResult.contraIndicators();
        List<String> ciReason = mapperResult.contraIndicatorReasons();
        List<String> ciChecks = mapperResult.contraIndicatorChecks();
        List<String> ciFailedChecks = mapperResult.contraIndicatorFailedChecks();

        assertNotNull(ciCodes);
        assertEquals(0, ciCodes.size());

        assertEquals(0, ciReason.size());

        // Two checks passed
        assertEquals(2, ciChecks.size());
        assertTrue(ciChecks.contains("four_check"));
        assertTrue(ciChecks.contains("five_check"));

        // No checks failed
        assertEquals(0, ciFailedChecks.size());
    }

    @Test
    void shouldReturnSingleCIAndOneSpecificReasonForFlagsInCiReasonsMultiMappingWhenBothMatch() {
        Map<String, String> testflagMap = new HashMap<>();
        testflagMap.put("flagSix", "true");
        testflagMap.put("flagSeven", "true");

        ContraIndicatorMapperResult mapperResult = contraIndicatorMapper.mapFlagsToCIs(testflagMap);

        assertNotNull(mapperResult);

        assertNotNull(mapperResult.contraIndicators());
        assertNotNull(mapperResult.contraIndicatorReasons());
        assertNotNull(mapperResult.contraIndicatorChecks());
        assertNotNull(mapperResult.contraIndicatorFailedChecks());

        List<String> ciCodes = mapperResult.contraIndicators();
        List<String> ciReason = mapperResult.contraIndicatorReasons();
        List<String> ciChecks = mapperResult.contraIndicatorChecks();
        List<String> ciFailedChecks = mapperResult.contraIndicatorFailedChecks();

        assertNotNull(ciCodes);
        assertEquals(1, ciCodes.size());
        assertTrue(ciCodes.contains("E05"));

        assertEquals(1, ciReason.size());

        // Seven is the general reason, Six is the specific
        assertTrue(ciReason.contains("E05,Six"));
        assertFalse(ciReason.contains("E05,Seven"));

        // No passed checks
        assertEquals(0, ciChecks.size());

        assertEquals(2, ciFailedChecks.size());
        assertTrue(ciFailedChecks.contains("six_check"));
        assertTrue(ciFailedChecks.contains("seven_check"));
    }

    @ParameterizedTest
    @CsvSource({
        "true", // specific present
        "false", // specific not present
    })
    void shouldReturnSingleCIAndOneGeneralReasonForFlagsInCiReasonsMultiMappingWhenOnlyGeneralMatch(
            boolean specificPresent) {
        Map<String, String> testflagMap = new HashMap<>();

        if (specificPresent) {
            testflagMap.put("flagSix", "false"); // Specific Present but value not matching
        }

        testflagMap.put("flagSeven", "true"); // General Match

        ContraIndicatorMapperResult mapperResult = contraIndicatorMapper.mapFlagsToCIs(testflagMap);

        assertNotNull(mapperResult);

        assertNotNull(mapperResult.contraIndicators());
        assertNotNull(mapperResult.contraIndicatorReasons());
        assertNotNull(mapperResult.contraIndicatorChecks());
        assertNotNull(mapperResult.contraIndicatorFailedChecks());

        List<String> ciCodes = mapperResult.contraIndicators();
        List<String> ciReason = mapperResult.contraIndicatorReasons();
        List<String> ciChecks = mapperResult.contraIndicatorChecks();
        List<String> ciFailedChecks = mapperResult.contraIndicatorFailedChecks();

        assertNotNull(ciCodes);
        assertEquals(1, ciCodes.size());
        assertTrue(ciCodes.contains("E05"));

        assertEquals(1, ciReason.size());

        // Seven is the general reason, Six is the specific
        assertFalse(ciReason.contains("E05,Six"));
        assertTrue(ciReason.contains("E05,Seven"));

        // Specific check has passed (when present)
        assertEquals(specificPresent ? 1 : 0, ciChecks.size());
        assertEquals(specificPresent, ciChecks.contains("six_check"));
        assertFalse(ciChecks.contains("seven_check"));

        assertEquals(1, ciFailedChecks.size());
        assertFalse(ciFailedChecks.contains("six_check"));
        assertTrue(ciFailedChecks.contains("seven_check"));
    }

    @Test
    void shouldReturnSingleCIAndTwoSpecificReasonForFlagsInCiReasonsTripleMapping() {
        Map<String, String> testflagMap = new HashMap<>();
        testflagMap.put("flagEight", "true");
        testflagMap.put("flagNine", "true");
        testflagMap.put("flagTen", "true");

        ContraIndicatorMapperResult mapperResult = contraIndicatorMapper.mapFlagsToCIs(testflagMap);

        assertNotNull(mapperResult);

        assertNotNull(mapperResult.contraIndicators());
        assertNotNull(mapperResult.contraIndicatorReasons());
        assertNotNull(mapperResult.contraIndicatorChecks());
        assertNotNull(mapperResult.contraIndicatorFailedChecks());

        List<String> ciCodes = mapperResult.contraIndicators();
        List<String> ciReason = mapperResult.contraIndicatorReasons();
        List<String> ciChecks = mapperResult.contraIndicatorChecks();
        List<String> ciFailedChecks = mapperResult.contraIndicatorFailedChecks();

        assertNotNull(ciCodes);
        assertEquals(1, ciCodes.size());
        assertTrue(ciCodes.contains("F06"));

        assertEquals(2, ciReason.size());

        // Ten is the general reason, Eight/Nine are the specific
        assertTrue(ciReason.contains("F06,Eight"));
        assertTrue(ciReason.contains("F06,Nine"));
        assertFalse(ciReason.contains("F06,Ten"));

        // No passed checks
        assertEquals(0, ciChecks.size());

        assertEquals(3, ciFailedChecks.size());
        assertTrue(ciFailedChecks.contains("eight_check"));
        assertTrue(ciFailedChecks.contains("nine_check"));
        assertTrue(ciFailedChecks.contains("ten_check"));
    }

    @Test
    void shouldReturnMapperResultWithEmptyListsIfNoFlagNoFlagsProvided() {
        Map<String, String> testflagMap = new HashMap<>();

        ContraIndicatorMapperResult mapperResult = contraIndicatorMapper.mapFlagsToCIs(testflagMap);

        assertNotNull(mapperResult);

        assertNotNull(mapperResult.contraIndicators());
        assertNotNull(mapperResult.contraIndicatorReasons());
        assertNotNull(mapperResult.contraIndicatorChecks());
        assertNotNull(mapperResult.contraIndicatorFailedChecks());

        assertEquals(0, mapperResult.contraIndicators().size());
        assertEquals(0, mapperResult.contraIndicatorReasons().size());
        assertEquals(0, mapperResult.contraIndicatorChecks().size());
        assertEquals(0, mapperResult.contraIndicatorFailedChecks().size());
    }

    @Test
    void shouldLogErrorIfUnmappedFlagsFound() {

        // Not used in this test, null to ensure accidental usage is spotted
        contraIndicatorMapper = null;

        // Mocks the logger creation and verifies the ERROR log line
        try (MockedStatic<LoggerFactory> mockedLogManager = mockStatic(LoggerFactory.class)) {
            Logger mockedStaticLogger = mock(Logger.class);
            mockedLogManager
                    .when(() -> LoggerFactory.getLogger(ContraIndicatorMapper.class))
                    .thenReturn(mockedStaticLogger);

            Map<String, String> testflagMap = new HashMap<>();
            testflagMap.put("flagOne", "false"); // Valid flag but not correct value
            testflagMap.put("unmappedFlagOne", "false");
            testflagMap.put("unmappedFlagTwo", "true");

            // ContraIndicatorMapper just for this test (so log mocking is only here)
            ContraIndicatorMapper testContraIndicatorMapper =
                    new ContraIndicatorMapper(mockServiceFactory);

            ContraIndicatorMapperResult mapperResult =
                    testContraIndicatorMapper.mapFlagsToCIs(testflagMap);

            // Note mocking suppresses error log line output in test
            // also note Flags output order is reversed
            verify(mockedStaticLogger)
                    .error("Unmapped flags encountered: {}", "unmappedFlagOne, unmappedFlagTwo");

            assertNotNull(mapperResult);

            assertNotNull(mapperResult.contraIndicators());
            assertNotNull(mapperResult.contraIndicatorReasons());
            assertNotNull(mapperResult.contraIndicatorChecks());
            assertNotNull(mapperResult.contraIndicatorFailedChecks());

            assertEquals(0, mapperResult.contraIndicators().size());
            assertEquals(0, mapperResult.contraIndicatorReasons().size());
            // one check passed, other two unmapped
            assertEquals(1, mapperResult.contraIndicatorChecks().size());
            assertEquals(0, mapperResult.contraIndicatorFailedChecks().size());
        }
    }
}
