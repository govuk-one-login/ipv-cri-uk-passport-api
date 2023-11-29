package uk.gov.di.ipv.cri.passport.checkpassport.services;

import lombok.Data;

@Data
public final class ContraIndicatorComplexMapping {

    private static final String ERROR_FORMAT = "Flag %s not in the expected camel case format";

    public final String ci;
    public final String reason;
    public final String check;

    public final String requiredFlagValue;

    public ContraIndicatorComplexMapping(String ci, String flag, String requiredFlagValue) {
        this.ci = ci;

        // assumes flag is camelCaseFormat - becoming CaseFormat
        String flagMinusPrefix = removeFlagPrefix(flag);

        this.reason = flagMinusPrefix;
        this.check = titleToSnakeCase(flagMinusPrefix) + "_check";
        this.requiredFlagValue = requiredFlagValue;
    }

    private String removeFlagPrefix(String flag) {

        int location = -1;
        for (int c = 0; c < flag.length(); c++) {
            if (Character.isUpperCase(flag.charAt(c))) {
                location = c;
                break;
            }
        }

        // Not -1 or 0 (first char)
        if (location >= 1) {
            return flag.substring(location);
        } else {
            String message = String.format(ERROR_FORMAT, flag);
            throw new IllegalStateException(message);
        }
    }

    private String titleToSnakeCase(String flag) {
        return flag.replaceAll("([a-z])([A-Z])", "$1_$2").toLowerCase();
    }

    public String getRequiredFlagValue() {
        return requiredFlagValue;
    }
}
