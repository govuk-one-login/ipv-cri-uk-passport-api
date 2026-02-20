package uk.gov.di.ipv.cri.passport.checkpassport.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.checkpassport.validation.JsonValidationUtility;
import uk.gov.di.ipv.cri.passport.checkpassport.validation.ValidationResult;
import uk.gov.di.ipv.cri.passport.library.PassportFormTestDataGenerator;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;

import java.time.LocalDate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

@ExtendWith(MockitoExtension.class)
class FormDataValidatorTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(FormDataValidatorTest.class);

    @Test
    void testFormDataValidatorNamesCannotBeNull() {

        final String TEST_STRING = null;

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();
        FormDataValidator formDataValidator = new FormDataValidator();

        passportFormData.setForenames(null);
        passportFormData.setSurname(TEST_STRING);

        ValidationResult<List<String>> validationResult =
                formDataValidator.validate(passportFormData);

        final String EXPECTED_ERROR_0 =
                "Forenames" + JsonValidationUtility.IS_NULL_ERROR_MESSAGE_SUFFIX;
        final String EXPECTED_ERROR_1 =
                "Surname" + JsonValidationUtility.IS_NULL_ERROR_MESSAGE_SUFFIX;

        LOGGER.info(validationResult.getError().toString());

        assertNull(passportFormData.getForenames());
        assertEquals(TEST_STRING, passportFormData.getSurname());
        assertEquals(2, validationResult.getError().size());
        assertEquals(EXPECTED_ERROR_0, validationResult.getError().get(0));
        assertEquals(EXPECTED_ERROR_1, validationResult.getError().get(1));
        assertFalse(validationResult.isValid());
    }

    @Test
    void testFormDataValidatorDOBCannotBeNull() {

        final LocalDate testLocalDate = null;

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();
        FormDataValidator formDataValidator = new FormDataValidator();

        passportFormData.setDateOfBirth(testLocalDate);

        ValidationResult<List<String>> validationResult =
                formDataValidator.validate(passportFormData);

        final String EXPECTED_ERROR =
                "DateOfBirth" + JsonValidationUtility.IS_NULL_ERROR_MESSAGE_SUFFIX;

        LOGGER.info(validationResult.getError().toString());

        assertEquals(testLocalDate, passportFormData.getDateOfBirth());
        assertEquals(1, validationResult.getError().size());
        assertEquals(EXPECTED_ERROR, validationResult.getError().get(0));
        assertFalse(validationResult.isValid());
    }

    @ParameterizedTest
    @CsvSource(
            value = {
                "null", // null
                "''", // Empty
                "NOT A NUMBER" // not an integer
            },
            nullValues = {"null"})
    void testFormDataValidatorPassportCannotBeNull(String invalidPassportNumber) {

        final String FIELD_NAME = "PassportNumber";

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();
        FormDataValidator formDataValidator = new FormDataValidator();

        passportFormData.setPassportNumber(invalidPassportNumber);

        ValidationResult<List<String>> validationResult =
                formDataValidator.validate(passportFormData);

        String expectedError = null;

        if (invalidPassportNumber == null) {
            expectedError = FIELD_NAME + JsonValidationUtility.IS_NULL_ERROR_MESSAGE_SUFFIX;
        } else if (invalidPassportNumber.isEmpty()) {
            expectedError = FIELD_NAME + JsonValidationUtility.IS_EMPTY_ERROR_MESSAGE_SUFFIX;
        } else if (invalidPassportNumber.equals("NOT A NUMBER")) {
            expectedError =
                    FIELD_NAME + JsonValidationUtility.FAIL_PARSING_INTEGER_ERROR_MESSAGE_SUFFIX;
        }

        LOGGER.info(validationResult.getError().toString());

        assertEquals(invalidPassportNumber, passportFormData.getPassportNumber());
        assertEquals(1, validationResult.getError().size());
        assertEquals(expectedError, validationResult.getError().get(0));
        assertFalse(validationResult.isValid());
    }

    @Test
    void testFormDataValidatorExpiryDateCannotBeNull() {

        final LocalDate testExpiryDate = null;

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();
        FormDataValidator formDataValidator = new FormDataValidator();

        passportFormData.setExpiryDate(testExpiryDate);

        ValidationResult<List<String>> validationResult =
                formDataValidator.validate(passportFormData);

        final String EXPECTED_ERROR =
                "ExpiryDate" + JsonValidationUtility.IS_NULL_ERROR_MESSAGE_SUFFIX;

        LOGGER.info(validationResult.getError().toString());

        assertEquals(testExpiryDate, passportFormData.getExpiryDate());
        assertEquals(1, validationResult.getError().size());
        assertEquals(EXPECTED_ERROR, validationResult.getError().get(0));
        assertFalse(validationResult.isValid());
    }
}
