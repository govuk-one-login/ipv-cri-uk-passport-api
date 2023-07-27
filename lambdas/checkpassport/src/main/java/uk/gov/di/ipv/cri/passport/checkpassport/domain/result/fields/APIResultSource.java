package uk.gov.di.ipv.cri.passport.checkpassport.domain.result.fields;

public enum APIResultSource {
    DCS("dcs"),
    DVAD("dvad");

    private final String name;

    APIResultSource(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
