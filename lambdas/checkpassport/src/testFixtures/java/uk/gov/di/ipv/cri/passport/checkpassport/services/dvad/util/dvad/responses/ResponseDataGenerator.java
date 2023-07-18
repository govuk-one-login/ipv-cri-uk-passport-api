package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.util.dvad.responses;

import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.ResponseData;

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
