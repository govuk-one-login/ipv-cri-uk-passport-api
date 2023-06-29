package uk.gov.di.ipv.cri.passport.checkpassport.services.dcs;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.request.dcs.ProtectedHeader;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.request.dcs.Thumbprints;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dcs.DcsResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dcs.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.checkpassport.exception.dcs.IpvCryptoException;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.helpers.KeyCertHelper;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Base64;
import java.util.Map;

import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_ENCRYPTION_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_PASSPORT_CRI_ENCRYPTION_KEY;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_PASSPORT_CRI_SIGNING_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_PASSPORT_CRI_SIGNING_KEY;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DCS_SIGNING_CERT;

public class DcsCryptographyService {

    private final PassportConfigurationService passportConfigurationService;
    private final Gson gson = new Gson();
    private final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());

    public DcsCryptographyService(PassportConfigurationService passportConfigurationService) {
        this.passportConfigurationService = passportConfigurationService;
    }

    public JWSObject preparePayload(PassportFormData passportFormData)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    JOSEException, JsonProcessingException, IpvCryptoException {
        JWSObject signedPassportDetails =
                createJWS(objectMapper.writeValueAsString(passportFormData));
        JWEObject encryptedPassportDetails = createJWE(signedPassportDetails.serialize());
        return createJWS(encryptedPassportDetails.serialize());
    }

    public DcsResponse unwrapDcsResponse(String dcsSignedEncryptedResponseString)
            throws CertificateException, ParseException, JOSEException {

        DcsSignedEncryptedResponse dcsSignedEncryptedResponse =
                new DcsSignedEncryptedResponse(dcsSignedEncryptedResponseString);

        JWSObject outerSignedPayload = JWSObject.parse(dcsSignedEncryptedResponse.getPayload());
        if (isInvalidSignature(outerSignedPayload)) {
            throw new IpvCryptoException("DCS Response Outer Signature invalid.");
        }
        JWEObject encryptedSignedPayload =
                JWEObject.parse(outerSignedPayload.getPayload().toString());
        JWSObject decryptedSignedPayload = decrypt(encryptedSignedPayload);
        if (isInvalidSignature(decryptedSignedPayload)) {
            throw new IpvCryptoException("DCS Response Inner Signature invalid.");
        }
        try {
            return objectMapper.readValue(
                    decryptedSignedPayload.getPayload().toString(), DcsResponse.class);
        } catch (JsonProcessingException exception) {
            throw new IpvCryptoException(
                    String.format(
                            "Failed to parse decrypted DCS response: %s", exception.getMessage()));
        }
    }

    private JWSObject createJWS(String stringToSign)
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException,
                    CertificateException {

        Thumbprints thumbprints = makeThumbprints(DCS_PASSPORT_CRI_SIGNING_CERT);

        ProtectedHeader protectedHeader =
                new ProtectedHeader(
                        JWSAlgorithm.RS256.toString(),
                        thumbprints.getSha1Thumbprint(),
                        thumbprints.getSha256Thumbprint());

        String jsonHeaders = gson.toJson(protectedHeader);

        JWSObject jwsObject =
                new JWSObject(
                        new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .customParams(
                                        gson.fromJson(
                                                jsonHeaders,
                                                new TypeToken<Map<String, Object>>() {}.getType()))
                                .build(),
                        new Payload(stringToSign));

        String base64String =
                passportConfigurationService.getEncryptedSsmParameter(DCS_PASSPORT_CRI_SIGNING_KEY);

        PrivateKey privateKey = KeyCertHelper.getDecodedPrivateRSAKey(base64String);

        jwsObject.sign(new RSASSASigner(privateKey));

        return jwsObject;
    }

    private Thumbprints makeThumbprints(String certificateParameter)
            throws CertificateException, NoSuchAlgorithmException {

        String base64String =
                passportConfigurationService.getEncryptedSsmParameter(certificateParameter);

        X509Certificate cert =
                (X509Certificate) KeyCertHelper.getDecodedX509Certificate(base64String);

        return new Thumbprints(getThumbprint(cert, "SHA-1"), getThumbprint(cert, "SHA-256"));
    }

    private String getThumbprint(X509Certificate cert, String hashAlg)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance(hashAlg);
        byte[] der = cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private JWEObject createJWE(String data)
            throws JOSEException, CertificateException, IpvCryptoException {

        var header =
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256)
                        .type(new JOSEObjectType("JWE"))
                        .build();
        var jwe = new JWEObject(header, new Payload(data));

        String base64String =
                passportConfigurationService.getEncryptedSsmParameter(DCS_ENCRYPTION_CERT);

        RSAPublicKey rsaPublicKey =
                (RSAPublicKey) KeyCertHelper.getDecodedX509Certificate(base64String).getPublicKey();

        jwe.encrypt(new RSAEncrypter(rsaPublicKey));

        if (!jwe.getState().equals(JWEObject.State.ENCRYPTED)) {
            throw new IpvCryptoException("Something went wrong, couldn't encrypt JWE");
        }

        return jwe;
    }

    private boolean isInvalidSignature(JWSObject jwsObject)
            throws CertificateException, JOSEException {

        String base64String =
                passportConfigurationService.getEncryptedSsmParameter(DCS_SIGNING_CERT);

        RSAPublicKey rsaPublicKey =
                (RSAPublicKey) KeyCertHelper.getDecodedX509Certificate(base64String).getPublicKey();

        RSASSAVerifier rsassaVerifier = new RSASSAVerifier(rsaPublicKey);

        return !jwsObject.verify(rsassaVerifier);
    }

    public JWSObject decrypt(JWEObject encrypted) {
        try {
            String base64String =
                    passportConfigurationService.getEncryptedSsmParameter(
                            DCS_PASSPORT_CRI_ENCRYPTION_KEY);

            PrivateKey privateKey = KeyCertHelper.getDecodedPrivateRSAKey(base64String);

            RSADecrypter rsaDecrypter = new RSADecrypter(privateKey);
            encrypted.decrypt(rsaDecrypter);

            return JWSObject.parse(encrypted.getPayload().toString());
        } catch (ParseException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | JOSEException exception) {
            throw new IpvCryptoException(
                    String.format("Cannot Decrypt DCS Payload: %s", exception.getMessage()));
        }
    }
}
