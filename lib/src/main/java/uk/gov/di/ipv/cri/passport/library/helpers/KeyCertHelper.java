package uk.gov.di.ipv.cri.passport.library.helpers;

import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class KeyCertHelper {

    @ExcludeFromGeneratedCoverageReport
    private KeyCertHelper() {
        throw new IllegalStateException("Instantiation is not valid for this class.");
    }

    public static X509Certificate getDecodedX509Certificate(String base64String)
            throws CertificateException {
        byte[] binaryCertificate = Base64.getDecoder().decode(base64String);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate)
                factory.generateCertificate(new ByteArrayInputStream(binaryCertificate));
    }

    public static PrivateKey getDecodedPrivateRSAKey(String base64String)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] binaryKey = Base64.getDecoder().decode(base64String);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(binaryKey);
        return factory.generatePrivate(privateKeySpec);
    }
}
