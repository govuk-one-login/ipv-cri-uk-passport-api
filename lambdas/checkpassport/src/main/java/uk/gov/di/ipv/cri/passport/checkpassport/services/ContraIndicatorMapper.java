package uk.gov.di.ipv.cri.passport.checkpassport.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

/**
 * Originally added to map values from sensitive fields from an earlier DVAD API spec. Left as a
 * similar CI mapping maybe needed in-future.
 */
public class ContraIndicatorMapper {
    private static final String MAPPING_DELIMITER = "\\|\\|"; // "||" (escaped)
    private static final String FLAGS_CI_DELIMITER = ":";
    private static final String FLAGS_DELIMITER = ",";
    private static final String FLAG_VALUE_DELIMITER = "@";

    private static final String CI_MAP = "CIMap";

    // Non-static as Log-line output in this class is tested
    private final Logger logger = LogManager.getLogger();

    private final Map<String, ContraIndicatorComplexMapping> flagCIMap;

    public ContraIndicatorMapper(ServiceFactory serviceFactory) {

        PassportConfigurationService passportConfigurationService =
                serviceFactory.getPassportConfigurationService();

        final String contraindicatorMappingString =
                System.getenv().get(CI_MAP) == null
                        ? passportConfigurationService.getParameterValue(CONTRAINDICATION_MAPPINGS)
                        : System.getenv().get(CI_MAP);

        flagCIMap = parseCIMappingString(contraindicatorMappingString);

        logger.info("CI Mappings ({})", flagCIMap.size());
    }

    /**
     * Parses a string representing the flag Mappings. Example :
     * CIMap=flag1@true,flag2@false:a1||flag3@40:b1 Represents : flag1:true -> a1 flag2:false -> a1
     * flag3:40 -> b1 where flag1 triggers if true, flag2 triggers if false Assumes we never map
     * flag to a second CICode.
     *
     * @param mappingString String with the mappings in above syntax
     * @return A map of flags to CI pairs
     */
    private Map<String, ContraIndicatorComplexMapping> parseCIMappingString(String mappingString) {

        logger.info("Parsing CI mapping string...");

        Map<String, ContraIndicatorComplexMapping> tempflagCIMap = new HashMap<>();

        String[] mappings = mappingString.split(MAPPING_DELIMITER);

        for (String mapping : mappings) {

            List<String> flagCIPairs = Arrays.asList(mapping.split(FLAGS_CI_DELIMITER));

            String[] flagNameValuePairs = flagCIPairs.get(0).split(FLAGS_DELIMITER);
            String ciCode = flagCIPairs.get(1);

            for (String flagNameValuePair : flagNameValuePairs) {

                String[] flagNameValuePairSplit = flagNameValuePair.split(FLAG_VALUE_DELIMITER);

                // Flag + Required Value to match the CI
                String flagName = flagNameValuePairSplit[0];
                String requiredValue = flagNameValuePairSplit[1];

                ContraIndicatorComplexMapping complexMapping =
                        new ContraIndicatorComplexMapping(ciCode, requiredValue);

                tempflagCIMap.put(flagName, complexMapping);
            }
        }

        return tempflagCIMap;
    }

    public List<String> mapFlagsToCIs(Map<String, String> flagMap) {
        Objects.requireNonNull(flagMap, "flagMap must not be null");

        if (flagMap.size() == 0) {
            logger.info("No flags to map");
            return new ArrayList<>();
        }

        List<String> contraIndicators =
                flagMap.keySet().stream()
                        .filter(flagCIMap::containsKey)
                        .filter(
                                flag -> {
                                    // Flag must be present and matching the required flag value
                                    String filterValue = flagCIMap.get(flag).requiredFlagValue;
                                    String flagValue = flagMap.get(flag);

                                    return filterValue.equals(flagValue);
                                })
                        .map(flag -> this.flagCIMap.get(flag).ci)
                        .collect(Collectors.toList());

        List<String> presentNotMatching =
                flagMap.keySet().stream()
                        .filter(flagCIMap::containsKey)
                        .filter(
                                flag -> {
                                    // Flag must be present and NOT matching the required flag value
                                    String filterValue = flagCIMap.get(flag).requiredFlagValue;
                                    String flagValue = flagMap.get(flag);

                                    return !filterValue.equals(flagValue);
                                })
                        .collect(Collectors.toList());

        logger.info("PresentNotMatching ({})", presentNotMatching.size());
        for (String pre : presentNotMatching) {
            logger.debug("PresentNotMatching : {}", pre);
        }

        int flagsInitialQuery = flagMap.size();
        int flagPresentNotMatching = presentNotMatching.size();

        int contraIndicatorsFound = contraIndicators.size();

        // ContraIndicators+flagPresentNotMatching must equal the flagMap size
        // If not, then the mappingString needs updated with the flags
        boolean hasUnmappedFlags =
                (flagsInitialQuery != (flagPresentNotMatching + contraIndicatorsFound));

        if (hasUnmappedFlags) {

            String[] unmappedFlags =
                    flagMap.keySet().stream()
                            .filter(flag -> !flagCIMap.containsKey(flag)) // Not present
                            .toArray(String[]::new);

            String unmappedFlagsAsString = String.join(", ", unmappedFlags);
            logger.error("Unmapped flags encountered: {}", unmappedFlagsAsString);
        }

        // contraIndicators list is put through a set to remove duplicate CI's
        return new ArrayList<>(Set.copyOf(contraIndicators));
    }
}
