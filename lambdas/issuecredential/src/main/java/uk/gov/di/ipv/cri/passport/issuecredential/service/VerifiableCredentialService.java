package uk.gov.di.ipv.cri.passport.issuecredential.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.BirthDate;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.Passport;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.PersonIdentityDetailed;
import uk.gov.di.ipv.cri.common.library.util.SignedJWTFactory;
import uk.gov.di.ipv.cri.common.library.util.VerifiableCredentialClaimsSetBuilder;
import uk.gov.di.ipv.cri.passport.issuecredential.util.EvidenceHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;

import java.time.Clock;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.cri.passport.issuecredential.domain.VerifiableCredentialConstants.VC_BIRTHDATE_KEY;
import static uk.gov.di.ipv.cri.passport.issuecredential.domain.VerifiableCredentialConstants.VC_CREDENTIAL_TYPE_ICC;
import static uk.gov.di.ipv.cri.passport.issuecredential.domain.VerifiableCredentialConstants.VC_NAME_KEY;
import static uk.gov.di.ipv.cri.passport.issuecredential.domain.VerifiableCredentialConstants.VC_PASSPORT_KEY;
import static uk.gov.di.ipv.cri.passport.library.config.GlobalConstants.UK_ICAO_ISSUER_CODE;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.MAX_JWT_TTL_UNIT;

public class VerifiableCredentialService {
    private ObjectMapper objectMapper;
    private PassportConfigurationService passportConfigurationService;
    private SignedJWTFactory signedJwtFactory;
    private VerifiableCredentialClaimsSetBuilder vcClaimsSetBuilder;

    public VerifiableCredentialService(ServiceFactory serviceFactory, JWSSigner jwsSigner) {
        this.objectMapper = serviceFactory.getObjectMapper();
        this.passportConfigurationService = serviceFactory.getPassportConfigurationService();

        this.signedJwtFactory = new SignedJWTFactory(jwsSigner);

        this.vcClaimsSetBuilder =
                new VerifiableCredentialClaimsSetBuilder(
                        passportConfigurationService, Clock.systemUTC());
    }

    public SignedJWT generateSignedVerifiableCredentialJwt(
            String subject,
            DocumentCheckResultItem documentCheckResultItem,
            PersonIdentityDetailed personIdentityDetailed)
            throws JOSEException {
        long jwtTtl = passportConfigurationService.getMaxJwtTtl();

        ChronoUnit jwtTtlUnit =
                ChronoUnit.valueOf(
                        passportConfigurationService.getStackParameterValue(MAX_JWT_TTL_UNIT));

        var claimsSet =
                this.vcClaimsSetBuilder
                        .subject(subject)
                        .timeToLive(jwtTtl, jwtTtlUnit)
                        .verifiableCredentialType(VC_CREDENTIAL_TYPE_ICC)
                        .verifiableCredentialSubject(
                                Map.of(
                                        VC_PASSPORT_KEY,
                                        convertPassport(documentCheckResultItem),
                                        VC_NAME_KEY,
                                        personIdentityDetailed.getNames(),
                                        VC_BIRTHDATE_KEY,
                                        convertBirthDates(personIdentityDetailed.getBirthDates())))
                        .verifiableCredentialEvidence(calculateEvidence(documentCheckResultItem))
                        .build();

        return signedJwtFactory.createSignedJwt(claimsSet);
    }

    private Object[] convertPassport(DocumentCheckResultItem documentCheckResultItem) {
        final Passport passport = new Passport();
        passport.setDocumentNumber(documentCheckResultItem.getDocumentNumber());
        passport.setExpiryDate(documentCheckResultItem.getExpiryDate());
        passport.setIcaoIssuerCode(UK_ICAO_ISSUER_CODE);

        return new Map[] {objectMapper.convertValue(passport, Map.class)};
    }

    private Object[] convertBirthDates(List<BirthDate> birthDates) {
        return birthDates.stream()
                .map(
                        birthDate ->
                                Map.of(
                                        "value",
                                        birthDate
                                                .getValue()
                                                .format(DateTimeFormatter.ISO_LOCAL_DATE)))
                .toArray();
    }

    private Object[] calculateEvidence(DocumentCheckResultItem documentCheckResultItem) {
        return new Map[] {
            objectMapper.convertValue(
                    EvidenceHelper.documentCheckResultItemToEvidence(documentCheckResultItem),
                    Map.class)
        };
    }
}
