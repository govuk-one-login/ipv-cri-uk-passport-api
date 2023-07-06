package uk.gov.di.ipv.cri.passport.issuecredential.domain.checkdetails;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"txn", "checkMethod", "passportCheck"})
public class Check {

    @JsonIgnore // @JsonProperty("passportCheck")
    private String passportCheck;

    @JsonProperty("checkMethod")
    private String checkMethod = "data";

    @JsonIgnore // @JsonProperty("txn")
    private String txn;

    public Check(String passportCheck) {
        this.passportCheck = passportCheck;
    }

    public String getPassportCheck() {
        return passportCheck;
    }

    public String getCheckMethod() {
        return checkMethod;
    }

    public String getTxn() {
        return txn;
    }

    public void setTxn(String txn) {
        this.txn = txn;
    }
}
