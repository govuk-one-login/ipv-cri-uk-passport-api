package uk.gov.di.ipv.cri.passport.checkpassport.domain.result;

public class ThirdPartyAPIResult {
    private String transactionId;
    private boolean isValid;

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
}
