package uk.gov.di.ipv.cri.passport.checkpassport.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.fields.ContraIndicatorMapperResult;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.CONTRAINDICATION_MAPPINGS;

/** Flags in the CI_MAP are sensitive fields. */
public class ContraIndicatorMapper {
    private static final String MAPPING_DELIMITER = "\\|\\|"; // "||" (escaped)
    private static final String FLAGS_CI_DELIMITER = ":";
    private static final String FLAGS_STANDARD_DELIMITER = ",";
    private static final String FLAGS_WITH_CI_REASON_SUB_SET_DELIMITER = ">";
    private static final String FLAG_VALUE_DELIMITER = "@";

    // CI:Reason
    private static final String CI_REASON_FORMAT = "%s,%s";

    private static final String CI_MAP = "CIMap";

    // Non-static as Log-line output in this class is tested
    private final Logger logger = LogManager.getLogger();

    // Indexed by Flag
    private final Map<String, ContraIndicatorComplexMapping> flagToContraIndicatorMappings =
            new HashMap<>();

    // If a reason is present also its more specific subset reason,
    // Then we only want the specific reason to appear in the result
    // Map Indexed by specific subset reason
    private final Map<String, ContraIndicatorComplexMapping> ciReasonSubSetMappings =
            new HashMap<>();

    public ContraIndicatorMapper(ServiceFactory serviceFactory) {

        PassportConfigurationService passportConfigurationService =
                serviceFactory.getPassportConfigurationService();

        final String contraindicatorMappingString =
                System.getenv().get(CI_MAP) == null
                        ? passportConfigurationService.getParameterValue(CONTRAINDICATION_MAPPINGS)
                        : System.getenv().get(CI_MAP);

        parseCIMappingStringAndPopulateMappings(contraindicatorMappingString);

        logger.info("CI Mappings ({})", flagToContraIndicatorMappings.size());
        logger.info("CI Reason Subset Mappings ({})", ciReasonSubSetMappings.size());
    }

    /**
     * Parses a string representing the flag Mappings.
     *
     * <pre>
     * Example Mapping : CIMap=flag1@true,flag2@false:a1||flag3@40:b1||flag4@true>flag5@true:c1
     * Example Format  : flag1@true,flag2@false:a1 - flag1 triggers if true, flag2 triggers if false CI is a1
     * Example Format  : flag3@40,flag2@false:a1   - flag3 triggers if value is 40 CI is b1
     * Example Format  : flag4@true>flag5@true:c1  - flag4 and flag5 trigger if true, if both trigger only the reason
     * for flag4 is used, as flag 5 is the general flag.
     * </pre>
     *
     * Assumes we never map the same flag to a second CICode.
     *
     * @param mappingString String with the mappings in above syntax
     */
    private void parseCIMappingStringAndPopulateMappings(String mappingString) {

        logger.info("Parsing CI mapping string...");

        String[] mappings = mappingString.split(MAPPING_DELIMITER);

        for (String mapping : mappings) {

            List<String> flagCIPairs = Arrays.asList(mapping.split(FLAGS_CI_DELIMITER));

            // Once set, this is used for the entire flag
            // using multiple delimiters for a single CI not supported
            boolean isCiReasonSubsetMapping =
                    flagCIPairs.get(0).contains(FLAGS_WITH_CI_REASON_SUB_SET_DELIMITER);

            final String ciPairDelimiter;
            if (isCiReasonSubsetMapping) {
                ciPairDelimiter = FLAGS_WITH_CI_REASON_SUB_SET_DELIMITER;
            } else {
                ciPairDelimiter = FLAGS_STANDARD_DELIMITER;
            }

            String[] flagNameValuePairs = flagCIPairs.get(0).split(ciPairDelimiter);
            String ciCode = flagCIPairs.get(1);

            List<ContraIndicatorComplexMapping> ciReasonsMappingAccumulator = new ArrayList<>();
            for (String flagNameValuePair : flagNameValuePairs) {

                String[] flagNameValuePairSplit = flagNameValuePair.split(FLAG_VALUE_DELIMITER);

                // Flag + Required Value to match the CI
                String flagName = flagNameValuePairSplit[0];
                String requiredValue = flagNameValuePairSplit[1];

                ContraIndicatorComplexMapping complexMapping =
                        new ContraIndicatorComplexMapping(ciCode, flagName, requiredValue);

                ciReasonsMappingAccumulator.add(complexMapping);

                flagToContraIndicatorMappings.put(flagName, complexMapping);
            }

            if (isCiReasonSubsetMapping) {
                int ciReasonsSize = ciReasonsMappingAccumulator.size();
                // Remove the last mapping as it is the general reason
                ContraIndicatorComplexMapping generalMapping =
                        ciReasonsMappingAccumulator.remove(ciReasonsSize - 1);

                for (ContraIndicatorComplexMapping specificMapping : ciReasonsMappingAccumulator) {
                    // Add the override for the general mapping to specific reason (mapping used as
                    // the CI is needed later)
                    // Can handle multiple overrides in the same mapping
                    ciReasonSubSetMappings.put(specificMapping.getReason(), generalMapping);
                }
            }
        }
    }

    public ContraIndicatorMapperResult mapFlagsToCIs(Map<String, String> flagMap) {
        Objects.requireNonNull(flagMap, "flagMap must not be null");

        if (flagMap.isEmpty()) {
            logger.info("No flags to map");
            return ContraIndicatorMapperResult.builder().build();
        }

        // Flag must be present and matching the required flag value
        List<ContraIndicatorComplexMapping> matchingCiMappings =
                flagMap.keySet().stream()
                        .filter(flagToContraIndicatorMappings::containsKey)
                        .filter(flag -> ciMapFilter(flagMap, flag))
                        .map(flagToContraIndicatorMappings::get)
                        .collect(Collectors.toList());

        int flagsPresentAndMatching = matchingCiMappings.size();
        logger.info("ContraIndicatorsFound ({})", flagsPresentAndMatching);

        // Flag must be present and NOT matching the required flag value
        List<ContraIndicatorComplexMapping> presentNotMatchingCiMappings =
                flagMap.keySet().stream()
                        .filter(flagToContraIndicatorMappings::containsKey)
                        .filter(flag -> !ciMapFilter(flagMap, flag)) // NOT
                        .map(flagToContraIndicatorMappings::get)
                        .collect(Collectors.toList());

        int flagPresentNotMatching = presentNotMatchingCiMappings.size();
        logger.info("PresentNotMatching ({})", flagPresentNotMatching);

        // ContraIndicators+flagPresentNotMatching must equal the flagMap size
        // If not, then the mappingString needs updated with the flags
        // Or there is a mistake in the mapping string
        int flagsInitialQuery = flagMap.size();
        boolean hasUnmappedFlags =
                (flagsInitialQuery != (flagPresentNotMatching + flagsPresentAndMatching));

        if (hasUnmappedFlags) {
            String[] unmappedFlags =
                    flagMap.keySet().stream()
                            .filter(
                                    flag ->
                                            !flagToContraIndicatorMappings.containsKey(
                                                    flag)) // Not present
                            .toArray(String[]::new);

            String unmappedFlagsAsString = String.join(", ", unmappedFlags);
            logger.error("Unmapped flags encountered: {}", unmappedFlagsAsString);
        }

        // contraIndicators list is put through a set to remove duplicate CI's
        List<String> contraIndicators =
                matchingCiMappings.stream()
                        .map(ContraIndicatorComplexMapping::getCi)
                        .collect(Collectors.toList());
        List<String> deDuplicatedContraIndicators = new ArrayList<>(Set.copyOf(contraIndicators));

        // "Ci,Reason" pair for ciReasons array (will be split in vc evidence)
        List<String> matchingCiReasons =
                matchingCiMappings.stream()
                        .map(
                                value ->
                                        String.format(
                                                CI_REASON_FORMAT, value.getCi(), value.getReason()))
                        .collect(Collectors.toList());

        // Apply CI reasons subset mapping rules
        List<String> specificReasons = new ArrayList<>(ciReasonSubSetMappings.keySet());

        // List used for reasonsToFilter in-case of multiple subsets of a general reason
        List<String> reasonsToFilter = new ArrayList<>();
        for (String specificReason : specificReasons) {

            ContraIndicatorComplexMapping generalMapping =
                    ciReasonSubSetMappings.get(specificReason);

            String ciSpecificReason =
                    String.format(CI_REASON_FORMAT, generalMapping.getCi(), specificReason);

            String ciGeneralReasonToFilterOut =
                    String.format(
                            CI_REASON_FORMAT, generalMapping.getCi(), generalMapping.getReason());

            // The final step is to only mark the general reason for removal
            // when the general and specific are both present
            // Otherwise leave the general reason
            if (matchingCiReasons.contains(ciGeneralReasonToFilterOut)
                    && matchingCiReasons.contains(ciSpecificReason)) {
                reasonsToFilter.add(ciGeneralReasonToFilterOut);
                logger.info(
                        "General CI reason {} suppressed in favour of specific reason {}",
                        ciGeneralReasonToFilterOut,
                        ciSpecificReason);
            }
        }

        // Now remove the filtered reasons
        // reason removal not done inline to support 2+ specifics
        // e.g. specific>specific>general mappings
        matchingCiReasons.removeAll(reasonsToFilter);

        // Checks Passed
        List<String> presentNotMatchingCiChecks =
                presentNotMatchingCiMappings.stream()
                        .map(ContraIndicatorComplexMapping::getCheck)
                        .collect(Collectors.toList());

        // Check Failed
        List<String> matchingCiChecks =
                matchingCiMappings.stream()
                        .map(ContraIndicatorComplexMapping::getCheck)
                        .collect(Collectors.toList());

        // Results of processing - lists never null
        return ContraIndicatorMapperResult.builder()
                .contraIndicators(deDuplicatedContraIndicators)
                .contraIndicatorReasons(matchingCiReasons)
                .contraIndicatorChecks(presentNotMatchingCiChecks)
                .contraIndicatorFailedChecks(matchingCiChecks)
                .build();
    }

    // Method around filter as the filter is used multiple times and needs to be the same
    private boolean ciMapFilter(Map<String, String> flagMap, String flag) {

        String filterValue = flagToContraIndicatorMappings.get(flag).requiredFlagValue;
        String flagValue = flagMap.get(flag);

        return filterValue.equals(flagValue);
    }
}
