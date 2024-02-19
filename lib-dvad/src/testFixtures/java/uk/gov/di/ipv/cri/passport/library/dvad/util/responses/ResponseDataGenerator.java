package uk.gov.di.ipv.cri.passport.library.dvad.util.responses;

import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields.ResponseData;

import java.util.HashMap;
import java.util.Map;

public class ResponseDataGenerator {

    // Sonar...
    private static final String FALSE = "false";

    private ResponseDataGenerator() {
        throw new IllegalStateException("Test Fixtures");
    }

    public static ResponseData createValidationResultTrueResponseData() {

        Map<String, String> validatePassport = new HashMap<>();

        validatePassport.put("validationResult", "true");

        return ResponseData.builder().validatePassport(validatePassport).build();
    }

    public static ResponseData createValidationResultFalseResponseData() {

        Map<String, String> validatePassport = new HashMap<>();

        validatePassport.put("validationResult", FALSE);

        return ResponseData.builder().validatePassport(validatePassport).build();
    }
}
