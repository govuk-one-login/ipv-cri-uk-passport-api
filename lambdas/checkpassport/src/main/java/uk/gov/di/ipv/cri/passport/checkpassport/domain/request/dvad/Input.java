package uk.gov.di.ipv.cri.passport.checkpassport.domain.request.dvad;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;

@NoArgsConstructor
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Input {

    private int passportNumber;
    private String forenames;
    private String surname;
    private String dateOfBirth;

    public Input(PassportFormData formData) {
        passportNumber = Integer.parseInt(formData.getPassportNumber());
        forenames = String.join(" ", formData.getForenames());
        surname = formData.getSurname();
        dateOfBirth = formData.getDateOfBirth().toString();
    }
}
