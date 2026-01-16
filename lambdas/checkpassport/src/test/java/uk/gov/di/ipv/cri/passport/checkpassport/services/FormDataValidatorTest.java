package uk.gov.di.ipv.cri.passport.checkpassport.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.checkpassport.validation.JsonValidationUtility;
import uk.gov.di.ipv.cri.passport.checkpassport.validation.ValidationResult;
import uk.gov.di.ipv.cri.passport.library.PassportFormTestDataGenerator;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;

import java.time.LocalDate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

@Tag("QualityGateUnitTest")
@ExtendWith(MockitoExtension.class)
class FormDataValidatorTest {

    private static final Logger LOGGER = LogManager.getLogger();

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

        final LocalDate TEST_LOCAL_DATE = null;

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();
        FormDataValidator formDataValidator = new FormDataValidator();

        passportFormData.setDateOfBirth(TEST_LOCAL_DATE);

        ValidationResult<List<String>> validationResult =
                formDataValidator.validate(passportFormData);

        final String EXPECTED_ERROR =
                "DateOfBirth" + JsonValidationUtility.IS_NULL_ERROR_MESSAGE_SUFFIX;

        LOGGER.info(validationResult.getError().toString());

        assertEquals(TEST_LOCAL_DATE, passportFormData.getDateOfBirth());
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

        String EXPECTED_ERROR = null;

        if (invalidPassportNumber == null) {
            EXPECTED_ERROR = FIELD_NAME + JsonValidationUtility.IS_NULL_ERROR_MESSAGE_SUFFIX;
        } else if (invalidPassportNumber.isEmpty()) {
            EXPECTED_ERROR = FIELD_NAME + JsonValidationUtility.IS_EMPTY_ERROR_MESSAGE_SUFFIX;
        } else if (invalidPassportNumber.equals("NOT A NUMBER")) {
            EXPECTED_ERROR =
                    FIELD_NAME + JsonValidationUtility.FAIL_PARSING_INTEGER_ERROR_MESSAGE_SUFFIX;
        }

        LOGGER.info(validationResult.getError().toString());

        assertEquals(invalidPassportNumber, passportFormData.getPassportNumber());
        assertEquals(1, validationResult.getError().size());
        assertEquals(EXPECTED_ERROR, validationResult.getError().get(0));
        assertFalse(validationResult.isValid());
    }

    @Test
    void testFormDataValidatorExpiryDateCannotBeNull() {

        final LocalDate TEST_EXPIRY_DATE = null;

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();
        FormDataValidator formDataValidator = new FormDataValidator();

        passportFormData.setExpiryDate(TEST_EXPIRY_DATE);

        ValidationResult<List<String>> validationResult =
                formDataValidator.validate(passportFormData);

        final String EXPECTED_ERROR =
                "ExpiryDate" + JsonValidationUtility.IS_NULL_ERROR_MESSAGE_SUFFIX;

        LOGGER.info(validationResult.getError().toString());

        assertEquals(TEST_EXPIRY_DATE, passportFormData.getExpiryDate());
        assertEquals(1, validationResult.getError().size());
        assertEquals(EXPECTED_ERROR, validationResult.getError().get(0));
        assertFalse(validationResult.isValid());
    }
}
