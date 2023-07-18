package uk.gov.di.ipv.cri.passport.checkpassport.services;

import uk.gov.di.ipv.cri.passport.checkpassport.validation.JsonValidationUtility;
import uk.gov.di.ipv.cri.passport.checkpassport.validation.ValidationResult;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class FormDataValidator {
    private static final int NAME_STRING_MAX_LEN = 1024;

    ValidationResult<List<String>> validate(PassportFormData passportForm) {
        List<String> validationErrors = new ArrayList<>();

        List<String> foreNames = passportForm.getForenames();
        if (JsonValidationUtility.validateListDataEmptyIsFail(
                foreNames, "Forenames", validationErrors)) {
            for (String name : passportForm.getForenames()) {
                JsonValidationUtility.validateStringDataEmptyIsFail(
                        name, NAME_STRING_MAX_LEN, "Forename", validationErrors);
            }
        }

        JsonValidationUtility.validateStringDataEmptyIsFail(
                passportForm.getSurname(), NAME_STRING_MAX_LEN, "Surname", validationErrors);

        if (Objects.isNull(passportForm.getDateOfBirth())) {
            validationErrors.add(
                    "DateOfBirth" + JsonValidationUtility.IS_NULL_ERROR_MESSAGE_SUFFIX);
        }

        JsonValidationUtility.validateIntegerStringNullOrEmptyIsFail(
                passportForm.getPassportNumber(), "PassportNumber", validationErrors);

        if (Objects.isNull(passportForm.getExpiryDate())) {
            validationErrors.add("ExpiryDate" + JsonValidationUtility.IS_NULL_ERROR_MESSAGE_SUFFIX);
        }

        // this implementation needs completing to validate all necessary fields
        return new ValidationResult<>(validationErrors.isEmpty(), validationErrors);
    }
}
