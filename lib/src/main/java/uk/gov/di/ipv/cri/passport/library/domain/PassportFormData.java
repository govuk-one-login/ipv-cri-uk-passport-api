package uk.gov.di.ipv.cri.passport.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class PassportFormData {
    private static final String DATE_FORMAT = "yyyy-MM-dd";
    private static final String TIMESTAMP_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSZ";

    private static final String TIME_ZONE = "UTC";

    @JsonProperty private UUID correlationId;
    @JsonProperty private UUID requestId;
    @JsonProperty private String timestamp;
    @JsonProperty private String passportNumber;
    @JsonProperty private String surname;

    @JsonFormat(with = JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY)
    public List<String> forenames;

    @JsonFormat(pattern = DATE_FORMAT, timezone = TIME_ZONE)
    public LocalDate dateOfBirth;

    @JsonFormat(pattern = DATE_FORMAT, timezone = TIME_ZONE)
    public LocalDate expiryDate;

    public PassportFormData() {}

    @JsonCreator
    public PassportFormData(
            @JsonProperty(value = "passportNumber", required = true) String passportNumber,
            @JsonProperty(value = "surname", required = true) String surname,
            @JsonProperty(value = "forenames", required = true) List<String> forenames,
            @JsonProperty(value = "dateOfBirth", required = true) LocalDate dateOfBirth,
            @JsonProperty(value = "expiryDate", required = true) LocalDate expiryDate) {
        this.passportNumber = passportNumber;
        this.surname = surname;
        this.forenames = forenames;
        this.dateOfBirth = dateOfBirth;
        this.expiryDate = expiryDate;
        this.correlationId = UUID.randomUUID();
        this.requestId = UUID.randomUUID();
        this.timestamp = new SimpleDateFormat(TIMESTAMP_DATE_FORMAT).format(new Date());
    }

    public UUID getCorrelationId() {
        return correlationId;
    }

    public void setCorrelationId(UUID correlationId) {
        this.correlationId = correlationId;
    }

    public UUID getRequestId() {
        return requestId;
    }

    public void setRequestId(UUID requestId) {
        this.requestId = requestId;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getPassportNumber() {
        return passportNumber;
    }

    public void setPassportNumber(String passportNumber) {
        this.passportNumber = passportNumber;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public List<String> getForenames() {
        return forenames;
    }

    public void setForenames(List<String> forenames) {
        this.forenames = forenames;
    }

    public LocalDate getDateOfBirth() {
        return dateOfBirth;
    }

    public void setDateOfBirth(LocalDate dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }

    public LocalDate getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(LocalDate expiryDate) {
        this.expiryDate = expiryDate;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PassportFormData that = (PassportFormData) o;
        return Objects.equals(correlationId, that.correlationId)
                && Objects.equals(requestId, that.requestId)
                && Objects.equals(timestamp, that.timestamp)
                && Objects.equals(passportNumber, that.passportNumber)
                && Objects.equals(surname, that.surname)
                && Objects.equals(forenames, that.forenames)
                && Objects.equals(dateOfBirth, that.dateOfBirth)
                && Objects.equals(expiryDate, that.expiryDate);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                correlationId,
                requestId,
                timestamp,
                passportNumber,
                surname,
                forenames,
                dateOfBirth,
                expiryDate);
    }

    @Override
    public String toString() {
        return "PassportAttributes{"
                + "correlationId="
                + correlationId
                + ", requestId="
                + requestId
                + ", timestamp='"
                + timestamp
                + ", passportNumber='"
                + passportNumber
                + ", surname='"
                + surname
                + ", forenames="
                + forenames
                + ", dateOfBirth="
                + dateOfBirth
                + ", expiryDate="
                + expiryDate
                + '}';
    }
}
