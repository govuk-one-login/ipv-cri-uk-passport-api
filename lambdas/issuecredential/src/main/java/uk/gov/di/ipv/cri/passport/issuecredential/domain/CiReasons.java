package uk.gov.di.ipv.cri.passport.issuecredential.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CiReasons {

    @JsonProperty("ci")
    private final String ci;

    @JsonProperty("reason")
    private final String reason;

    public CiReasons(String ci, String reason) {
        this.ci = ci;
        this.reason = reason;
    }

    public String getCi() {
        return ci;
    }

    public String getReason() {
        return reason;
    }
}
