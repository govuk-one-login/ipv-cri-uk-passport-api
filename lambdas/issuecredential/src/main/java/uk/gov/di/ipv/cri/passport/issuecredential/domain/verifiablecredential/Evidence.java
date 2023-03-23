package uk.gov.di.ipv.cri.passport.issuecredential.domain.verifiablecredential;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.issuecredential.domain.checkdetails.Check;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Evidence {

    private String type = "IdentityCheck";
    private String txn;
    private int strengthScore;
    private int validityScore;
    private List<String> ci;

    @JsonIgnore // @JsonProperty("checkDetails")
    private List<Check> checkDetails;

    @JsonIgnore // @JsonProperty("failedCheckDetails")
    private List<Check> failedCheckDetails;

    public Evidence() {}

    public Evidence(String txn, int strengthScore, int validityScore, List<String> ci) {
        this.txn = txn;
        this.strengthScore = strengthScore;
        this.validityScore = validityScore;
        this.ci = ci;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getTxn() {
        return txn;
    }

    public void setTxn(String txn) {
        this.txn = txn;
    }

    public int getStrengthScore() {
        return strengthScore;
    }

    public void setStrengthScore(int strengthScore) {
        this.strengthScore = strengthScore;
    }

    public int getValidityScore() {
        return validityScore;
    }

    public void setValidityScore(int validityScore) {
        this.validityScore = validityScore;
    }

    public List<String> getCi() {
        return ci;
    }

    public void setCi(List<String> ci) {
        this.ci = ci;
    }

    public void setCheckDetails(List<Check> checkDetails) {
        this.checkDetails = checkDetails;
    }

    public List<Check> getFailedCheckDetails() {
        return failedCheckDetails;
    }

    public void setFailedCheckDetails(List<Check> failedCheckDetails) {
        this.failedCheckDetails = failedCheckDetails;
    }

    @Override
    public String toString() {
        return "Evidence{"
                + "type="
                + type
                + ", txn="
                + txn
                + ", strength="
                + strengthScore
                + ", validity="
                + validityScore
                + ", ci="
                + ci
                + '}';
    }
}
