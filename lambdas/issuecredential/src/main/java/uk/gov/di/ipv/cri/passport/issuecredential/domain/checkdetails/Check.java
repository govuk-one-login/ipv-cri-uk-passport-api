package uk.gov.di.ipv.cri.passport.issuecredential.domain.checkdetails;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"txn", "checkMethod", "dataCheck"})
public class Check {

    @JsonProperty("dataCheck")
    private String dataCheck;

    @JsonProperty("checkMethod")
    private String checkMethod = "data";

    @JsonIgnore // @JsonProperty("txn")
    private String txn;

    public Check(String dataCheck) {
        this.dataCheck = dataCheck;
    }

    public String getDataCheck() {
        return dataCheck;
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
