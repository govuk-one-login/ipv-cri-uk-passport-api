package uk.gov.di.ipv.cri.passport.library.dvad.util.responses;

import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields.errors.Errors;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields.errors.Extensions;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields.errors.Locations;

import java.util.List;

public class GraphQLAPIErrorDataGenerator {

    private GraphQLAPIErrorDataGenerator() {
        // Intended
    }

    public static Errors createAPIErrorScenario(String scenario) {
        switch (scenario) {
            case "ClassificationIsObject":
                return createAPIValidationError("Passport Number");
            case "ClassificationIsString":
                return createAPISystemError();
            case "NullTestCaseError":
                return createNullTestCaseError();
            case "EmptyTestCaseError":
                return createEmptyTestCaseError();
            default: // MinimalTestCaseError
                return createMinimalTestCaseError();
        }
    }

    // Error Format where classification is object but has been serialized to a string
    public static Errors createAPIValidationError(String passportFieldName) {
        String classification =
                "{\"classification\":\"{\"StringField1\":\"StringField1 Value\",\"StringArray\":[\"StringArray1\",\"StringArray2\",\"StringArray3\"],\"constraint\":\"StringField2 Value\"}\"}";

        return Errors.builder()
                .message("Validation Failure " + passportFieldName)
                .locations(List.of(Locations.builder().line("1").column("1").build()))
                .path(List.of("Passport"))
                .extensions(Extensions.builder().classification(classification).build())
                .build();
    }

    public static Errors createAPISystemError() {
        return Errors.builder()
                .message("Simulated System Error")
                .locations(List.of())
                .extensions(
                        Extensions.builder()
                                .errorCode("Error001")
                                .classification("AN_ERROR_OCCURRED")
                                .build())
                .build();
    }

    private static Errors createNullTestCaseError() {
        return Errors.builder()
                .message(null)
                .locations(null)
                .path(null)
                .locations(null)
                .extensions(Extensions.builder().errorCode(null).classification(null).build())
                .build();
    }

    private static Errors createEmptyTestCaseError() {
        return Errors.builder()
                .message("")
                .locations(List.of())
                .path(List.of())
                .locations(List.of())
                .extensions(Extensions.builder().errorCode("").classification("").build())
                .build();
    }

    private static Errors createMinimalTestCaseError() {
        return Errors.builder()
                .message("AlwaysPresent")
                .locations(List.of()) // Always Present but can be empty
                .extensions(Extensions.builder().classification("AlwaysPresent").build())
                .build();
    }
}
