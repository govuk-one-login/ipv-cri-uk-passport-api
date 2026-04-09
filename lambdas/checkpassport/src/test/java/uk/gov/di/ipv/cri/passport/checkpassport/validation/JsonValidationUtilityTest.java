package uk.gov.di.ipv.cri.passport.checkpassport.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonValidationUtilityTest {

    private static List<String> testList;
    private static String testString;
    private static int testInt;
    private static final int TEST_INT_RANGE_MIN = 0;
    private static final int TEST_INT_RANGE_MAX = 127;
    private static List<String> validationErrors;

    private static final String TEST_LIST_NAME = "TestList";
    private static final String TEST_STRING_NAME = "TestString";
    private static final String TEST_INTEGER_NAME = "TestInteger";

    @BeforeEach
    void PreEachTestSetup() {
        testList = new ArrayList<>();
        testString = "";
        testInt = 0;
        validationErrors = new ArrayList<>();
    }

    @Test
    void staticJsonValidationUtilityClassIsFinal() {
        boolean finalClass = Modifier.isFinal(JsonValidationUtility.class.getModifiers());
        assertTrue(finalClass);
    }

    @Test
    void staticJsonValidationUtilityClassCannotBeInstantiated() throws NoSuchMethodException {

        Constructor<JsonValidationUtility> constructor =
                JsonValidationUtility.class.getDeclaredConstructor();

        constructor.setAccessible(true);
        assertThrows(InvocationTargetException.class, constructor::newInstance);

        boolean privateConstructor = Modifier.isPrivate(constructor.getModifiers());

        assertTrue(privateConstructor);
    }

    @Test
    void validateListDataEmptyIsAllowed_PassesWithEmptyList() {
        boolean result =
                JsonValidationUtility.validateListDataEmptyIsAllowed(
                        testList, TEST_LIST_NAME, validationErrors);

        assertEquals(0, testList.size());
        assertEquals(0, validationErrors.size());
        assertTrue(result);
    }

    @Test
    void validateListDataEmptyIsAllowed_PassesWithFilledList() {
        testString = "Test";
        testList.add(testString);

        boolean result =
                JsonValidationUtility.validateListDataEmptyIsAllowed(
                        testList, TEST_LIST_NAME, validationErrors);

        assertEquals(1, testList.size());
        assertEquals(testString, testList.get(0));
        assertEquals(0, validationErrors.size());
        assertTrue(result);
    }

    @Test
    void validateListDataEmptyIsAllowed_FailsWithNullList() {
        testList = null;

        final String EXPECTED_ERROR =
                TEST_LIST_NAME + JsonValidationUtility.IS_NULL_ERROR_MESSAGE_SUFFIX;

        boolean result =
                JsonValidationUtility.validateListDataEmptyIsAllowed(
                        testList, TEST_LIST_NAME, validationErrors);

        assertEquals(1, validationErrors.size());
        assertEquals(EXPECTED_ERROR, validationErrors.get(0));
        assertFalse(result);
    }

    @Test
    void validateListDataEmptyIsFail_PassesWithFilledList() {
        testString = "Test";
        testList.add(testString);

        boolean result =
                JsonValidationUtility.validateListDataEmptyIsFail(
                        testList, TEST_LIST_NAME, validationErrors);

        assertEquals(1, testList.size());
        assertEquals(testString, testList.get(0));
        assertEquals(0, validationErrors.size());
        assertTrue(result);
    }

    @Test
    void validateListDataEmptyIsFail_FailsWithNullList() {
        testList = null;

        final String EXPECTED_ERROR =
                TEST_LIST_NAME + JsonValidationUtility.IS_NULL_ERROR_MESSAGE_SUFFIX;

        boolean result =
                JsonValidationUtility.validateListDataEmptyIsFail(
                        testList, TEST_LIST_NAME, validationErrors);

        assertEquals(1, validationErrors.size());
        assertEquals(EXPECTED_ERROR, validationErrors.get(0));
        assertFalse(result);
    }

    @Test
    void validateListDataEmptyIsFail_FailsWithEmptyList() {
        testList = new ArrayList<>();

        final String EXPECTED_ERROR =
                TEST_LIST_NAME + JsonValidationUtility.IS_EMPTY_ERROR_MESSAGE_SUFFIX;

        boolean result =
                JsonValidationUtility.validateListDataEmptyIsFail(
                        testList, TEST_LIST_NAME, validationErrors);

        assertEquals(1, validationErrors.size());
        assertEquals(EXPECTED_ERROR, validationErrors.get(0));
        assertFalse(result);
    }

    @Test
    void validateStringDataEmptyIsFail_PassesWithFilledString() {
        testString = "Test";
        final int TEST_LENGTH = testString.length();

        boolean result =
                JsonValidationUtility.validateStringDataEmptyIsFail(
                        testString, TEST_LENGTH, TEST_STRING_NAME, validationErrors);

        assertEquals(0, validationErrors.size());
        assertTrue(result);
    }

    @Test
    void validateStringDataEmptyIsFail_FailsWithEmptyString() {
        testString = "";
        final int TEST_LENGTH = Integer.MAX_VALUE;

        final String EXPECTED_ERROR =
                TEST_STRING_NAME + JsonValidationUtility.IS_EMPTY_ERROR_MESSAGE_SUFFIX;

        boolean result =
                JsonValidationUtility.validateStringDataEmptyIsFail(
                        testString, TEST_LENGTH, TEST_STRING_NAME, validationErrors);

        assertEquals(1, validationErrors.size());
        assertEquals(EXPECTED_ERROR, validationErrors.get(0));
        assertFalse(result);
    }

    @Test
    void validateStringDataEmptyIsFail_FailsWithNullString() {
        testString = null;
        final int TEST_LENGTH = Integer.MAX_VALUE;

        final String EXPECTED_ERROR =
                TEST_STRING_NAME + JsonValidationUtility.IS_NULL_ERROR_MESSAGE_SUFFIX;

        boolean result =
                JsonValidationUtility.validateStringDataEmptyIsFail(
                        testString, TEST_LENGTH, TEST_STRING_NAME, validationErrors);

        assertEquals(1, validationErrors.size());
        assertEquals(EXPECTED_ERROR, validationErrors.get(0));
        assertFalse(result);
    }

    @Test
    void validateStringDataEmptyIsFail_FailsWithTooLongString() {

        testString = "Test";
        final int TEST_LENGTH = testString.length() - 1;

        final String EXPECTED_ERROR =
                TEST_STRING_NAME + JsonValidationUtility.IS_TOO_LONG_ERROR_MESSAGE_SUFFIX;

        boolean result =
                JsonValidationUtility.validateStringDataEmptyIsFail(
                        testString, TEST_LENGTH, TEST_STRING_NAME, validationErrors);

        assertEquals(1, validationErrors.size());
        assertEquals(EXPECTED_ERROR, validationErrors.get(0));
        assertFalse(result);
    }

    @Test
    void validateStringDataEmptyIsAllowed_PassesWithFilledString() {
        testString = "Test";
        final int TEST_LENGTH = testString.length();

        boolean result =
                JsonValidationUtility.validateStringDataEmptyIsAllowed(
                        testString, TEST_LENGTH, TEST_STRING_NAME, validationErrors);

        assertEquals(0, validationErrors.size());
        assertTrue(result);
    }

    @Test
    void validateStringDataEmptyIsAllowed_PassesWithEmptyString() {
        testString = "";
        final int TEST_LENGTH = testString.length();

        boolean result =
                JsonValidationUtility.validateStringDataEmptyIsAllowed(
                        testString, TEST_LENGTH, TEST_STRING_NAME, validationErrors);

        assertEquals(0, validationErrors.size());
        assertTrue(result);
    }

    @Test
    void validateStringDataEmptyIsAllowed_FailsWithNullString() {
        testString = null;
        final int TEST_LENGTH = Integer.MAX_VALUE;

        final String EXPECTED_ERROR =
                TEST_STRING_NAME + JsonValidationUtility.IS_NULL_ERROR_MESSAGE_SUFFIX;

        boolean result =
                JsonValidationUtility.validateStringDataEmptyIsAllowed(
                        testString, TEST_LENGTH, TEST_STRING_NAME, validationErrors);

        assertEquals(1, validationErrors.size());
        assertEquals(EXPECTED_ERROR, validationErrors.get(0));
        assertFalse(result);
    }

    @Test
    void validateStringDataEmptyIsAllowed_FailsWithTooLongString() {
        testString = "Test";
        final int TEST_LENGTH = testString.length() - 1;

        final String EXPECTED_ERROR =
                TEST_STRING_NAME + JsonValidationUtility.IS_TOO_LONG_ERROR_MESSAGE_SUFFIX;

        boolean result =
                JsonValidationUtility.validateStringDataEmptyIsAllowed(
                        testString, TEST_LENGTH, TEST_STRING_NAME, validationErrors);

        assertEquals(1, validationErrors.size());
        assertEquals(EXPECTED_ERROR, validationErrors.get(0));
        assertFalse(result);
    }

    @Test
    void validateStringDataNullAndEmptyIsAllowedPassesWithFilledString() {
        testString = "Test";
        final int TEST_LENGTH = testString.length();

        boolean result =
                JsonValidationUtility.validateStringDataNullAndEmptyIsAllowed(
                        testString, TEST_LENGTH, TEST_STRING_NAME, validationErrors);

        assertEquals(0, validationErrors.size());
        assertTrue(result);
    }

    @Test
    void validateStringDataNullAndEmptyIsAllowed_PassesWithEmptyString() {
        testString = "";
        final int TEST_LENGTH = testString.length();

        boolean result =
                JsonValidationUtility.validateStringDataNullAndEmptyIsAllowed(
                        testString, TEST_LENGTH, TEST_STRING_NAME, validationErrors);

        assertEquals(0, validationErrors.size());
        assertTrue(result);
    }

    @Test
    void validateStringDataNullAndEmptyIsAllowed_PassesWithNullString() {
        testString = null;
        final int TEST_LENGTH = Integer.MAX_VALUE;

        boolean result =
                JsonValidationUtility.validateStringDataNullAndEmptyIsAllowed(
                        testString, TEST_LENGTH, TEST_STRING_NAME, validationErrors);

        assertEquals(0, validationErrors.size());
        assertTrue(result);
    }

    @Test
    void validateStringDataNullAndEmptyIsAllowed_FailsWithTooLongString() {
        testString = "Test";
        final int TEST_LENGTH = testString.length() - 1;

        final String EXPECTED_ERROR =
                TEST_STRING_NAME + JsonValidationUtility.IS_TOO_LONG_ERROR_MESSAGE_SUFFIX;

        boolean result =
                JsonValidationUtility.validateStringDataNullAndEmptyIsAllowed(
                        testString, TEST_LENGTH, TEST_STRING_NAME, validationErrors);

        assertEquals(1, validationErrors.size());
        assertEquals(EXPECTED_ERROR, validationErrors.get(0));
        assertFalse(result);
    }

    @Test
    void validateTimeStampData_PassesWithValidTimeStamp() {
        testString = "2022-01-01T00:00:01Z";

        boolean result =
                JsonValidationUtility.validateTimeStampData(
                        testString, TEST_STRING_NAME, validationErrors);

        assertEquals(0, validationErrors.size());
        assertTrue(result);
    }

    @Test
    void validateTimeStampData_FailsWithNullString() {
        testString = null;

        boolean result =
                JsonValidationUtility.validateTimeStampData(
                        testString, TEST_STRING_NAME, validationErrors);

        final String EXPECTED_ERROR =
                TEST_STRING_NAME + JsonValidationUtility.IS_NULL_ERROR_MESSAGE_SUFFIX;

        assertEquals(1, validationErrors.size());
        assertEquals(EXPECTED_ERROR, validationErrors.get(0));
        assertFalse(result);
    }

    @Test
    void validateTimeStampData_FailsWithEmptyString() {
        testString = "";

        boolean result =
                JsonValidationUtility.validateTimeStampData(
                        testString, TEST_STRING_NAME, validationErrors);

        final String EXPECTED_ERROR =
                TEST_STRING_NAME + JsonValidationUtility.IS_EMPTY_ERROR_MESSAGE_SUFFIX;

        assertEquals(1, validationErrors.size());
        assertEquals(EXPECTED_ERROR, validationErrors.get(0));
        assertFalse(result);
    }

    @Test
    void validateTimeStampData_FailsWithInvalidTimeStamp() {
        testString = "123";

        boolean result =
                JsonValidationUtility.validateTimeStampData(
                        testString, TEST_STRING_NAME, validationErrors);

        final String EXPECTED_ERROR =
                TEST_STRING_NAME
                        + JsonValidationUtility.FAIL_PARSING_TIMESTAMP_ERROR_MESSAGE_SUFFIX;

        assertEquals(1, validationErrors.size());
        assertEquals(EXPECTED_ERROR, validationErrors.get(0));
        assertFalse(result);
    }

    @Test
    void validateIntegerRangeData_PassesWithinRange() {
        testInt = 63;

        boolean result =
                JsonValidationUtility.validateIntegerRangeData(
                        testInt,
                        TEST_INT_RANGE_MIN,
                        TEST_INT_RANGE_MAX,
                        "TEST_INTEGER_NAME",
                        validationErrors);

        assertEquals(0, validationErrors.size());
        assertTrue(result);
    }

    @Test
    void validateIntegerRangeData_PassesAtMinRange() {
        testInt = TEST_INT_RANGE_MIN;

        boolean result =
                JsonValidationUtility.validateIntegerRangeData(
                        testInt,
                        TEST_INT_RANGE_MIN,
                        TEST_INT_RANGE_MAX,
                        "TEST_INTEGER_NAME",
                        validationErrors);

        assertEquals(0, validationErrors.size());
        assertTrue(result);
    }

    @Test
    void validateIntegerRangeData_PassesAtMaxRange() {
        testInt = TEST_INT_RANGE_MAX;

        boolean result =
                JsonValidationUtility.validateIntegerRangeData(
                        testInt,
                        TEST_INT_RANGE_MIN,
                        TEST_INT_RANGE_MAX,
                        "TEST_INTEGER_NAME",
                        validationErrors);

        assertEquals(0, validationErrors.size());
        assertTrue(result);
    }

    @Test
    void validateIntegerRangeData_FailsUnderMinRange() {
        testInt = TEST_INT_RANGE_MIN - 1;

        boolean result =
                JsonValidationUtility.validateIntegerRangeData(
                        testInt,
                        TEST_INT_RANGE_MIN,
                        TEST_INT_RANGE_MAX,
                        TEST_INTEGER_NAME,
                        validationErrors);

        final String EXPECTED_ERROR =
                JsonValidationUtility.createIntegerRangeErrorMessage(
                        testInt, TEST_INT_RANGE_MIN, TEST_INT_RANGE_MAX, TEST_INTEGER_NAME);

        assertEquals(1, validationErrors.size());
        assertEquals(EXPECTED_ERROR, validationErrors.get(0));
        assertFalse(result);
    }

    @Test
    void validateIntegerRangeData_FailsOverMaxRange() {
        testInt = TEST_INT_RANGE_MAX + 1;

        boolean result =
                JsonValidationUtility.validateIntegerRangeData(
                        testInt,
                        TEST_INT_RANGE_MIN,
                        TEST_INT_RANGE_MAX,
                        TEST_INTEGER_NAME,
                        validationErrors);

        final String EXPECTED_ERROR =
                JsonValidationUtility.createIntegerRangeErrorMessage(
                        testInt, TEST_INT_RANGE_MIN, TEST_INT_RANGE_MAX, TEST_INTEGER_NAME);

        assertEquals(1, validationErrors.size());
        assertEquals(EXPECTED_ERROR, validationErrors.get(0));
        assertFalse(result);
    }
}
