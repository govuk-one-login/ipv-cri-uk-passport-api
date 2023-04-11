package uk.gov.di.ipv.cri.passport.library.helpers;

import uk.gov.di.ipv.cri.common.library.domain.personidentity.BirthDate;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.Name;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.NamePart;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.PersonIdentityDetailed;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class PersonIdentityDetailedHelperMapper {

    private PersonIdentityDetailedHelperMapper() {
        throw new IllegalStateException("Instantiation is not valid for this class.");
    }

    public static PersonIdentityDetailed passportFormDataToAuditRestrictedFormat(
            PassportFormData passportFormData) {

        Name name1 =
                mapNamesToCanonicalName(
                        passportFormData.getForenames(), passportFormData.getSurname());

        BirthDate birthDate = new BirthDate();
        birthDate.setValue(passportFormData.getDateOfBirth());

        // TODO Add Passport
        // Set passport fields...

        // No Address+ Driving Permit, with Passport
        return new PersonIdentityDetailed(List.of(name1), List.of(birthDate), null);
    }

    public static Name mapNamesToCanonicalName(List<String> forenames, String surname) {
        List<NamePart> nameParts = new ArrayList<>();

        if (Objects.nonNull(forenames) && !forenames.isEmpty()) {
            for (String name : forenames) {
                nameParts.add(setNamePart(name, "GivenName"));
            }
        }

        if (Objects.nonNull(surname)) {
            nameParts.add(setNamePart(surname, "FamilyName"));
        }

        Name name1 = new Name();
        name1.setNameParts(nameParts);
        return name1;
    }

    private static NamePart setNamePart(String value, String type) {
        NamePart namePart = new NamePart();
        namePart.setValue(value);
        namePart.setType(type);
        return namePart;
    }
}
