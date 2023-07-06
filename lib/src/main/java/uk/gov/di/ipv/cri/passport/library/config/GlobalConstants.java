package uk.gov.di.ipv.cri.passport.library.config;

import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

public final class GlobalConstants {
    // United Kingdom Passports - ISO 3166-1 alpha-3
    public static final String UK_ICAO_ISSUER_CODE = "GBR";

    @ExcludeFromGeneratedCoverageReport
    private GlobalConstants() {
        throw new IllegalStateException("Instantiation is not valid for this class.");
    }
}
