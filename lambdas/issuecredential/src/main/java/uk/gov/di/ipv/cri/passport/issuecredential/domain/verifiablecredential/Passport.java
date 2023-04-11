package uk.gov.di.ipv.cri.passport.issuecredential.domain.verifiablecredential;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

public class Passport {

    @JsonProperty(value = "documentNumber")
    private String documentNumber;

    @JsonProperty(value = "icaoIssuerCode")
    private String icaoIssuerCode;

    @JsonProperty(value = "expiryDate")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private String expiryDate;

    public String getDocumentNumber() {
        return documentNumber;
    }

    public void setDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
    }

    public String getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(String expiryDate) {
        this.expiryDate = expiryDate;
    }

    public String getIcaoIssuerCode() {
        return icaoIssuerCode;
    }

    public void setIcaoIssuerCode(String icaoIssuerCode) {
        this.icaoIssuerCode = icaoIssuerCode;
    }
}
