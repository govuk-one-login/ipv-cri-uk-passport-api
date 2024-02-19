package uk.gov.di.ipv.cri.passport.library.domain.result;

import lombok.Data;
import uk.gov.di.ipv.cri.passport.library.domain.result.fields.APIResultSource;

import java.util.Map;

@Data
public class ThirdPartyAPIResult {

    private APIResultSource apiResultSource;

    // Legacy API transactionId and also holds new api requestId
    private String transactionId;

    private boolean isValid;

    private Map<String, String> flags;
}
