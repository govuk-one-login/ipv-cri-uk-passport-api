package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.util.dvad.responses;

import lombok.experimental.UtilityClass;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.errors.Classification;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.errors.Errors;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.errors.Extensions;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.fields.errors.Locations;

import java.util.List;

@UtilityClass
public class GraphQLAPIErrorDataGenerator {
    public static Errors createAPIError(String passportFieldName) {
        return Errors.builder()
                .message(passportFieldName + " not valid")
                .locations(List.of(Locations.builder().line("1").column("1").build()))
                .path(List.of("Passport"))
                .extensions(
                        Extensions.builder()
                                .classification(
                                        Classification.builder()
                                                .type("Validation Error")
                                                .validatedPath(
                                                        List.of(
                                                                "Passport",
                                                                "data",
                                                                passportFieldName))
                                                .constraint("Value")
                                                .build())
                                .build())
                .build();
    }
}
