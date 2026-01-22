package uk.gov.di.ipv.cri.passport.library.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.BirthDate;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.Name;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.Passport;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.PersonIdentityDetailed;
import uk.gov.di.ipv.cri.passport.library.DocumentCheckTestDataGenerator;
import uk.gov.di.ipv.cri.passport.library.PassportFormTestDataGenerator;
import uk.gov.di.ipv.cri.passport.library.config.GlobalConstants;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@ExtendWith(MockitoExtension.class)
class PersonIdentityDetailedHelperMapperTest {

    @Test
    void ShouldReturnAuditRestrictedFormatFromPassportFormData() {

        PassportFormData passportFormData = PassportFormTestDataGenerator.generate();

        PersonIdentityDetailed testPersonIdentityDetailedFromFormData =
                PersonIdentityDetailedHelperMapper.passportFormDataToAuditRestrictedFormat(
                        passportFormData);

        Name pidName = testPersonIdentityDetailedFromFormData.getNames().get(0);
        assertEquals(
                passportFormData.getForenames().get(0), pidName.getNameParts().get(0).getValue());
        assertEquals(
                passportFormData.getForenames().get(1), pidName.getNameParts().get(1).getValue());
        assertEquals(passportFormData.getSurname(), pidName.getNameParts().get(2).getValue());
        assertEquals(
                passportFormData.getDateOfBirth(),
                testPersonIdentityDetailedFromFormData.getBirthDates().get(0).getValue());

        // Passport
        Passport passport = testPersonIdentityDetailedFromFormData.getPassports().get(0);
        assertEquals(passportFormData.getPassportNumber(), passport.getDocumentNumber());
        assertEquals(passportFormData.getExpiryDate().toString(), passport.getExpiryDate());
        assertEquals(GlobalConstants.UK_ICAO_ISSUER_CODE, passport.getIcaoIssuerCode());

        // No address
        assertNull(testPersonIdentityDetailedFromFormData.getAddresses());
    }

    @Test
    void ShouldReturnAuditRestrictedFormatFromPersonIdentityDetailedAndDocumentCheckResultItem() {

        PassportFormData onlyUsedToGenerateData = PassportFormTestDataGenerator.generate();
        PersonIdentityDetailed testPersonIdentityDetailedFromFormData =
                PersonIdentityDetailedHelperMapper.passportFormDataToAuditRestrictedFormat(
                        onlyUsedToGenerateData);

        DocumentCheckResultItem testDocumentCheckResultItem =
                DocumentCheckTestDataGenerator.generateVerifiedResultItem(
                        UUID.randomUUID(), onlyUsedToGenerateData.getPassportNumber());

        // Called in IssueCredentialHandler where the original form data object is not available
        PersonIdentityDetailed auditPersonIdentityDetailed =
                PersonIdentityDetailedHelperMapper
                        .mapPersonIdentityDetailedAndPassportDataToAuditRestricted(
                                testPersonIdentityDetailedFromFormData,
                                testDocumentCheckResultItem);

        Name namePIDFormData = testPersonIdentityDetailedFromFormData.getNames().get(0);
        Name namePIDAudit = auditPersonIdentityDetailed.getNames().get(0);
        assertEquals(
                namePIDFormData.getNameParts().get(0).getValue(),
                namePIDAudit.getNameParts().get(0).getValue());
        assertEquals(
                namePIDFormData.getNameParts().get(1).getValue(),
                namePIDAudit.getNameParts().get(1).getValue());
        assertEquals(
                namePIDFormData.getNameParts().get(2).getValue(),
                namePIDAudit.getNameParts().get(2).getValue());

        BirthDate dobPIDFormData = testPersonIdentityDetailedFromFormData.getBirthDates().get(0);
        BirthDate dobPIDAudit = auditPersonIdentityDetailed.getBirthDates().get(0);
        assertEquals(dobPIDFormData.getValue(), dobPIDAudit.getValue());

        // Passport
        Passport passportPIDFormData = testPersonIdentityDetailedFromFormData.getPassports().get(0);
        Passport passportPIDAudit = testPersonIdentityDetailedFromFormData.getPassports().get(0);

        assertEquals(passportPIDFormData.getDocumentNumber(), passportPIDAudit.getDocumentNumber());
        assertEquals(passportPIDFormData.getExpiryDate(), passportPIDAudit.getExpiryDate());

        // Both should be hardcoded
        assertEquals(GlobalConstants.UK_ICAO_ISSUER_CODE, passportPIDFormData.getIcaoIssuerCode());
        assertEquals(GlobalConstants.UK_ICAO_ISSUER_CODE, passportPIDAudit.getIcaoIssuerCode());

        // No address
        assertNull(testPersonIdentityDetailedFromFormData.getAddresses());
        assertNull(auditPersonIdentityDetailed.getAddresses());
    }

    @Test
    void shouldMapNamesToCanonicalName() {

        String foreName = "Forename";
        String middleName = "Middlename";
        String surname = "Surname";

        Name name =
                PersonIdentityDetailedHelperMapper.mapNamesToCanonicalName(
                        List.of(foreName, middleName), surname);

        assertEquals(3, name.getNameParts().size());

        assertEquals(foreName, name.getNameParts().get(0).getValue());
        assertEquals("GivenName", name.getNameParts().get(0).getType());

        assertEquals(middleName, name.getNameParts().get(1).getValue());
        assertEquals("GivenName", name.getNameParts().get(1).getType());

        assertEquals(surname, name.getNameParts().get(2).getValue());
        assertEquals("FamilyName", name.getNameParts().get(2).getType());
    }

    @Test
    void shouldMapNullNameToEmptyCanonicalName() {
        Name name = PersonIdentityDetailedHelperMapper.mapNamesToCanonicalName(null, null);
        assertEquals(0, name.getNameParts().size());
    }

    @Test
    void shouldMapEmptyNameToEmptyCanonicalName() {
        Name name =
                PersonIdentityDetailedHelperMapper.mapNamesToCanonicalName(new ArrayList<>(), null);
        assertEquals(0, name.getNameParts().size());
    }
}
