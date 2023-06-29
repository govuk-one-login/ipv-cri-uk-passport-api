package uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dcs;

public class DcsSignedEncryptedResponse {
    private final String payload;

    public DcsSignedEncryptedResponse(String payload) {
        this.payload = payload;
    }

    public String getPayload() {
        return payload;
    }
}
