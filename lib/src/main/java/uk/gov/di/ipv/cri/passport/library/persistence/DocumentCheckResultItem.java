package uk.gov.di.ipv.cri.passport.library.persistence;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class DocumentCheckResultItem {

    private UUID sessionId;
    private String transactionId;
    private int strengthScore;
    private int validityScore;
    private List<String> contraIndicators;
    private String documentNumber;
    private String expiryDate;

    private List<String> checkDetails;
    private List<String> failedCheckDetails;

    private long ttl;

    @DynamoDbPartitionKey()
    public UUID getSessionId() {
        return sessionId;
    }

    public void setSessionId(UUID sessionId) {
        this.sessionId = sessionId;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
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

    public List<String> getContraIndicators() {
        return contraIndicators;
    }

    public void setContraIndicators(List<String> contraIndicators) {
        this.contraIndicators = contraIndicators;
    }

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

    public List<String> getCheckDetails() {
        return checkDetails;
    }

    public void setCheckDetails(List<String> checkDetails) {
        this.checkDetails = checkDetails;
    }

    public List<String> getFailedCheckDetails() {
        return failedCheckDetails;
    }

    public void setFailedCheckDetails(List<String> failedCheckDetails) {
        this.failedCheckDetails = failedCheckDetails;
    }

    public long getTtl() {
        return ttl;
    }

    public void setTtl(long ttl) {
        this.ttl = ttl;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DocumentCheckResultItem that = (DocumentCheckResultItem) o;
        return strengthScore == that.strengthScore
                && validityScore == that.validityScore
                && Objects.equals(sessionId, that.sessionId)
                && Objects.equals(transactionId, that.transactionId)
                && Objects.equals(contraIndicators, that.contraIndicators)
                && Objects.equals(documentNumber, that.documentNumber)
                && Objects.equals(expiryDate, that.expiryDate)
                && Objects.equals(checkDetails, that.checkDetails)
                && Objects.equals(failedCheckDetails, that.failedCheckDetails);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                sessionId,
                transactionId,
                strengthScore,
                validityScore,
                contraIndicators,
                documentNumber,
                expiryDate,
                checkDetails,
                failedCheckDetails,
                ttl);
    }
}
