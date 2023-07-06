package uk.gov.di.ipv.cri.passport.checkpassport.domain.request.dvad;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.cri.passport.library.config.GlobalConstants;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;

@NoArgsConstructor
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Input {

    private String passportNumber;
    private String nationalityCode;
    private String forenames;
    private String surname;
    private String dateOfBirth;
    private String dateOfIssue;
    private String dateOfExpiry;
    private String placeOfBirth;
    private String gender;
    private String previousSurname;
    private String bookType;

    public Input(PassportFormData formData) {
        passportNumber = formData.getPassportNumber();
        nationalityCode = GlobalConstants.UK_ICAO_ISSUER_CODE;
        forenames = String.join(" ", formData.getForenames());
        surname = formData.getSurname();
        dateOfBirth = formData.getDateOfBirth().toString();
        dateOfExpiry = formData.getExpiryDate().toString();
    }
}
