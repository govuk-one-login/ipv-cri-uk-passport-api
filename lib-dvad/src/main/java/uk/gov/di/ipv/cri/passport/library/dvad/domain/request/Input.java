package uk.gov.di.ipv.cri.passport.library.dvad.domain.request;

import com.fasterxml.jackson.annotation.JsonInclude;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record Input(int passportNumber, String forenames, String surname, String dateOfBirth) {
    public Input(PassportFormData formData) {
        this(
                Integer.parseInt(formData.getPassportNumber()),
                String.join(" ", formData.getForenames()),
                formData.getSurname(),
                formData.getDateOfBirth().toString());
    }
}
