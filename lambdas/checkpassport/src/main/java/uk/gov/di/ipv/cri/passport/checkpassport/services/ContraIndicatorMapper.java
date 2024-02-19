package uk.gov.di.ipv.cri.passport.checkpassport.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.fields.ContraIndicatorMapperResult;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;
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

        ParameterStoreService parameterStoreService = serviceFactory.getParameterStoreService();

        final String contraindicatorMappingString =
                System.getenv().get(CI_MAP) == null
                        ? parameterStoreService.getParameterValue(CONTRAINDICATION_MAPPINGS)
                        : System.getenv().get(CI_MAP);

        parseCIMappingStringAndPopulateMappings(contraindicatorMappingString);

        logger.info("CI Mappings ({})", flagToContraIndicatorMappings.size());
        logger.info("CI Reason Subset Mappings ({})", ciReasonSubSetMappings.size());
    }

    // Should move away from > in case were ever return xml etc
    // NOTE. For the purpose of this ticket the mapper has remained is
    /**
     * Parses a string representing the flag Mappings.
     *
     * <pre>
     * Example Mapping : CIMap=flag1@true,flag2@false:a1||flag3@40:b1||flag4@true>flag5@true:c1
     * Example Format  : flag1@true,flag2@false:a1 - flag1 triggers if true, flag2 triggers if false CI is a1
     * Example Format  : flag3@40,flag2@false:b1   - flag3 triggers if value is 40 CI is b1
     * Example Format  : flag4@true>flag5@true:c1  - flag4 and flag5 trigger if true, if both trigger only the reason
     * for flag4 is used, as flag 5 is the general flag.
     * </pre>
     *
     * Assumes we never map the same flag to a second CICode.
     *
     * @param mappingString String with the mappings in above syntax
     */
    // JB could return accumlator and split into 2 methods
    private void parseCIMappingStringAndPopulateMappings(String mappingString) {

        logger.info("Parsing CI mapping string...");

        String[] mappings = mappingString.split(MAPPING_DELIMITER);

        for (String mapping : mappings) {

            List<String> flagCIPairs = Arrays.asList(mapping.split(FLAGS_CI_DELIMITER));

            final String ciPairDelimiter = FLAGS_STANDARD_DELIMITER;

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

            // Remove the first mapping as it is the general reason
            // TODO not sure about this requires the mapper to be in a very specific order
            // Is this because it contains the D01
            ContraIndicatorComplexMapping generalMapping = ciReasonsMappingAccumulator.remove(0);

            for (ContraIndicatorComplexMapping specificMapping : ciReasonsMappingAccumulator) {
                // Add the override for the general mapping to specific reason (mapping used as
                // the CI is needed later)
                // Can handle multiple overrides in the same mapping
                ciReasonSubSetMappings.put(specificMapping.getReason(), generalMapping);
            }
        }
    }

    public ContraIndicatorMapperResult mapFlagsToCIs(Map<String, String> flagMap) {
        Objects.requireNonNull(flagMap, "flagMap must not be null");

        if (flagMap.isEmpty()) {
            logger.info("No flags to map");
            return ContraIndicatorMapperResult.builder().build();
        }

        List<ContraIndicatorComplexMapping> matchingCiMappings = new ArrayList<>();
        List<ContraIndicatorComplexMapping> presentNotMatchingCiMappings = new ArrayList<>();
        List<String> unmappedFlags = new ArrayList<>();

        for (Map.Entry<String, String> entry : flagMap.entrySet()) {
            if (flagToContraIndicatorMappings.containsKey(entry.getKey())) {
                if (ciMapFilter(flagMap, entry.getKey())) {
                    matchingCiMappings.add(flagToContraIndicatorMappings.get(entry.getKey()));
                } else {
                    presentNotMatchingCiMappings.add(
                            flagToContraIndicatorMappings.get(entry.getKey()));
                }
            } else {
                unmappedFlags.add(entry.getKey());
            }
        }

        logCIsAndUnmatchedFlags(
                flagMap, matchingCiMappings, presentNotMatchingCiMappings, unmappedFlags);

        List<String> contraIndicators = new ArrayList<>();
        List<String> matchingCiReasons = new ArrayList<>();
        for (ContraIndicatorComplexMapping matchedCiMapping : matchingCiMappings) {
            contraIndicators.add(matchedCiMapping.getCi());
            matchingCiReasons.add(
                    String.format(
                            CI_REASON_FORMAT,
                            matchedCiMapping.getCi(),
                            matchedCiMapping.getReason()));
        }
        // contraIndicators list is put through a set to remove duplicate CI's
        List<String> deDuplicatedContraIndicators = new ArrayList<>(Set.copyOf(contraIndicators));
        List<String> reasonsToFilterOut = getTopLevelReasons(matchingCiReasons);

        // Now remove the filtered reasons
        // reason removal not done inline to support 2+ specifics
        // e.g. general,specific mappings
        matchingCiReasons.removeAll(reasonsToFilterOut);

        // Could also potentially be absorbed above
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

    private void logCIsAndUnmatchedFlags(
            Map<String, String> flagMap,
            List<ContraIndicatorComplexMapping> matchingCiMappings,
            List<ContraIndicatorComplexMapping> presentNotMatchingCiMappings,
            List<String> unmappedFlags) {
        int flagsPresentAndMatching = matchingCiMappings.size();
        logger.info("ContraIndicatorsFound ({})", flagsPresentAndMatching);

        int flagPresentNotMatching = presentNotMatchingCiMappings.size();
        logger.info("PresentNotMatching ({})", flagPresentNotMatching);

        // ContraIndicators+flagPresentNotMatching must equal the flagMap size
        // If not, then the mappingString needs updated with the flags
        // Or there is a mistake in the mapping string

        // Flag map size is number of flags we have documented
        int flagsInitialQuery = flagMap.size();
        boolean hasUnmappedFlags =
                (flagsInitialQuery != (flagPresentNotMatching + flagsPresentAndMatching));

        if (hasUnmappedFlags) {
            // Unmapped flags would indicate HMPO are sending something were not prepared for
            String unmappedFlagsAsString = String.join(", ", unmappedFlags);
            logger.error("Unmapped flags encountered: {}", unmappedFlagsAsString);
        }
    }

    private List<String> getTopLevelReasons(List<String> matchingCiReasons) {
        // Apply CI reasons subset mapping rules

        // List used for reasonsToFilter in-case of multiple subsets of a general reason
        // basing logic on response

        //  would it be better in an HMPO specific file
        List<String> reasonsToFilter = new ArrayList<>();
        for (String specificReason : ciReasonSubSetMappings.keySet()) {

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
        return reasonsToFilter;
    }

    // Method around filter as the filter is used multiple times and needs to be the same
    private boolean ciMapFilter(Map<String, String> flagMap, String flag) {

        String filterValue = flagToContraIndicatorMappings.get(flag).getRequiredFlagValue();
        String flagValue = flagMap.get(flag);

        return filterValue.equals(flagValue);
    }
}
