package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.util.dvad.responses;

import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.ResponseData;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.ValidatePassportData;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.ValidationResult;

import java.util.HashMap;
import java.util.Map;

public class ResponseDataGenerator {

    // Sonar...
    private static final String FALSE = "false";

    private ResponseDataGenerator() {
        throw new IllegalStateException("Test Fixtures");
    }

    public static ResponseData createValidSuccessResponseData() {

        Map<String, String> matches = new HashMap<>();

        matches.put("flag1", FALSE);
        matches.put("flag2", FALSE);
        matches.put("flag3", FALSE);
        matches.put("flagA", FALSE);
        matches.put("flagB", FALSE);
        matches.put("flagC", FALSE);

        ValidatePassportData validatePassportData =
                ValidatePassportData.builder()
                        .validationResult(ValidationResult.SUCCESS)
                        .passportFound(true)
                        .matches(matches)
                        .build();

        return ResponseData.builder().validatePassportData(validatePassportData).build();
    }

    public static ResponseData createValidNotFoundResponseData() {

        ValidatePassportData validatePassportData =
                ValidatePassportData.builder()
                        .validationResult(ValidationResult.FAILURE)
                        .passportFound(false)
                        .matches(null)
                        .build();

        return ResponseData.builder().validatePassportData(validatePassportData).build();
    }
}
