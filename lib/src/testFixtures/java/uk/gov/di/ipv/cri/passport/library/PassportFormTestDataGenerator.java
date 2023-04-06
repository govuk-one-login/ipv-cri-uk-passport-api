package uk.gov.di.ipv.cri.passport.library;

import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.List;

public class PassportFormTestDataGenerator {
    private PassportFormTestDataGenerator() {
        throw new IllegalStateException("Instantiation is not valid for this class.");
    }

    public static PassportFormData generate() {
        PassportFormData passportFormData = new PassportFormData();

        passportFormData.setForenames(List.of("FirstName", "MiddleName"));
        passportFormData.setSurname("Surname");

        passportFormData.setDateOfBirth(LocalDate.of(1999, 1, 1));

        passportFormData.setPassportNumber("123456789");

        passportFormData.setExpiryDate(LocalDate.now().plus(5, ChronoUnit.YEARS));

        return passportFormData;
    }
}
