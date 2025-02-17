package uk.gov.di.ipv.cri.passport.library.helpers;

import uk.gov.di.ipv.cri.common.library.domain.personidentity.BirthDate;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.Name;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.NamePart;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.Passport;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.PersonIdentityDetailed;
import uk.gov.di.ipv.cri.common.library.service.PersonIdentityDetailedFactory;
import uk.gov.di.ipv.cri.passport.library.config.GlobalConstants;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static uk.gov.di.ipv.cri.passport.library.config.GlobalConstants.UK_ICAO_ISSUER_CODE;

public class PersonIdentityDetailedHelperMapper {

    private PersonIdentityDetailedHelperMapper() {
        // Utility Class
    }

    public static PersonIdentityDetailed mapPersonIdentityDetailedAndPassportDataToAuditRestricted(
            PersonIdentityDetailed personIdentityDetailed,
            DocumentCheckResultItem documentCheckResultItem) {

        List<Name> names = personIdentityDetailed.getNames();
        List<BirthDate> birthDates = personIdentityDetailed.getBirthDates();

        Passport passport = new Passport();
        passport.setDocumentNumber(documentCheckResultItem.getDocumentNumber());
        passport.setExpiryDate(documentCheckResultItem.getExpiryDate());
        passport.setIcaoIssuerCode(GlobalConstants.UK_ICAO_ISSUER_CODE);
        List<Passport> passports = List.of(passport);

        return PersonIdentityDetailedFactory.createPersonIdentityDetailedWithPassport(
                names, birthDates, passports);
    }

    public static PersonIdentityDetailed passportFormDataToAuditRestrictedFormat(
            PassportFormData passportFormData) {

        Name name =
                mapNamesToCanonicalName(
                        passportFormData.getForenames(), passportFormData.getSurname());
        List<Name> names = List.of(name);

        BirthDate birthDate = new BirthDate();
        birthDate.setValue(passportFormData.getDateOfBirth());
        List<BirthDate> birthDates = List.of(birthDate);

        Passport passport = new Passport();
        passport.setDocumentNumber(passportFormData.getPassportNumber());
        passport.setExpiryDate(passportFormData.getExpiryDate().toString());
        passport.setIcaoIssuerCode(UK_ICAO_ISSUER_CODE);
        List<Passport> passports = List.of(passport);

        return PersonIdentityDetailedFactory.createPersonIdentityDetailedWithPassport(
                names, birthDates, passports);
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
