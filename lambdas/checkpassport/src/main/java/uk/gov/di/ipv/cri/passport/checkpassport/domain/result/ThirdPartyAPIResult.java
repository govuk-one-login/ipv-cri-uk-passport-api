package uk.gov.di.ipv.cri.passport.checkpassport.domain.result;

import lombok.Data;

import java.util.Map;

@Data
public class ThirdPartyAPIResult {
    // Legacy API transactionId and also holds new api requestId
    private String transactionId;
    private boolean isValid;

    private Map<String, String> flags;
}
