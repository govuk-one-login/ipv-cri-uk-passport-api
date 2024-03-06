package uk.gov.di.ipv.cri.passport.library.domain.result.fields;

import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public enum APIResultSource {
    DVAD("dvad");

    private final String name;

    APIResultSource(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
