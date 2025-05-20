package uk.gov.di.ipv.cri.passport.library.domain.result;

import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.domain.result.fields.APIResultSource;

import java.util.Map;

public class ThirdPartyAPIResult {

    private APIResultSource apiResultSource;

    // Legacy API transactionId and also holds new api requestId
    private String transactionId;

    private boolean isValid;

    private Map<String, String> flags;

    @ExcludeFromGeneratedCoverageReport
    public ThirdPartyAPIResult() {
        // intended
    }

    public APIResultSource getApiResultSource() {
        return apiResultSource;
    }

    public void setApiResultSource(APIResultSource apiResultSource) {
        this.apiResultSource = apiResultSource;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public boolean isValid() {
        return isValid;
    }

    public void setValid(boolean valid) {
        isValid = valid;
    }

    public Map<String, String> getFlags() {
        return flags;
    }

    public void setFlags(Map<String, String> flags) {
        this.flags = flags;
    }
}
