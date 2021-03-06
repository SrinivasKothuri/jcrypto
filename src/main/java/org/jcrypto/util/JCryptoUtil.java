package org.jcrypto.util;

import com.google.common.collect.ImmutableMap;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.EnumUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.joda.time.MutableDateTime;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.apache.commons.lang3.StringUtils.EMPTY;

public class JCryptoUtil {

    public static final String CERT_PREFIX = "-----BEGIN CERTIFICATE-----";
    public static final String CERT_SUFFIX = "-----END CERTIFICATE-----";

    public static final String PUB_KEY_PREFIX = "-----BEGIN RSA PUBLIC KEY-----";
    public static final String PUB_KEY_SUFFIX = "-----END RSA PUBLIC KEY-----";

    public static final String PRIVATE_KEY_PREFIX = "-----BEGIN RSA PRIVATE KEY-----";
    public static final String PRIVATE_KEY_SUFFIX = "-----END RSA PRIVATE KEY-----";

    private static final String LINE_SEPARATOR = System.lineSeparator();
    private static final String WRAPPED_FORMAT = "%s" + LINE_SEPARATOR + "%s" + LINE_SEPARATOR + "%s";

    private static final ImmutableMap<CertAttr, String> EMPTY_NAME =
            ImmutableMap.of(CertAttr.CN, EMPTY, CertAttr.C, EMPTY, CertAttr.O, EMPTY);

    public enum CertAttr {
        CN(0x01, BCStyle.CN, "Common Name"), O(0x02, BCStyle.O, "Organization"),
        OU(0x04, BCStyle.OU, "Organization Unit"), C(0x08, BCStyle.C, "Country"),
        L(0x10, BCStyle.L, "Locality"), ST(0x20, BCStyle.ST, "State or Province"),
        Email(0x40, BCStyle.EmailAddress, "Email");

        private final int fCode;

        private final ASN1ObjectIdentifier fBCCode;
        private final String fDefaultName;

        CertAttr(int code, ASN1ObjectIdentifier bCCode, String defaultName) {
            fCode = code;
            fBCCode = bCCode;
            fDefaultName = defaultName;
        }

        public int getCode() {
            return fCode;
        }

        public String getDefaultName() {
            return fDefaultName;
        }
    }

    public enum KeyFormat {
        PEM, DER
    }

    public static X500Name createNameFromMap(Map<CertAttr, String> certAttributes) {
        X500NameBuilder issuerBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        certAttributes.keySet().stream().forEach(
                key -> issuerBuilder.addRDN(key.fBCCode, certAttributes.get(key)));
        return issuerBuilder.build();
    }

    public static Map<CertAttr, String> parseX509Name(String x509Name) {
        String[] names = StringUtils.split(x509Name, ",");
        if (ArrayUtils.isEmpty(names))
            return Collections.EMPTY_MAP;

        Map<CertAttr, String> attrsMap = new HashMap<>();
        for (String name: names) {
            String[] nameSplit = StringUtils.split(name, '=');
            if (ArrayUtils.getLength(nameSplit) < 2 ||
                    !EnumUtils.isValidEnumIgnoreCase(CertAttr.class, nameSplit[0]) ||
                    StringUtils.isBlank(nameSplit[1]))
                continue;
            attrsMap.put(CertAttr.valueOf(nameSplit[0].trim().toUpperCase()), nameSplit[1].trim());
        }
        return attrsMap;
    }

    public static String getLocalizedName(CertAttr certAttr) {
        //TODO: handle localization
        return certAttr.getDefaultName();
    }

    public static void storePEMCertificate(String sourceDir, String fileName, byte[] encoded) throws IOException {
        store(sourceDir, fileName, KeyFormat.PEM, encoded, CERT_PREFIX, CERT_SUFFIX);
    }

    public static void storePrivateKey(KeyFormat format, String sourceDir, String fileName, byte[] encoded)
            throws IOException {
        if (format == KeyFormat.PEM)
            storePEMPrivateKey(sourceDir, fileName, encoded);
        else
            storeDERPrivateKey(sourceDir, fileName, encoded);
    }

    public static void storePublicKey(KeyFormat format, String sourceDir, String fileName, byte[] encoded)
            throws IOException {
        if (format == KeyFormat.PEM)
            storePEMPublicKey(sourceDir, fileName, encoded);
        else
            storeDERPublicKey(sourceDir, fileName, encoded);
    }

    public static void storePEMPrivateKey(String sourceDir, String fileName, byte[] encoded) throws IOException {
        store(sourceDir, fileName, KeyFormat.PEM, encoded, PRIVATE_KEY_PREFIX, PRIVATE_KEY_SUFFIX);
    }

    public static void storePEMPublicKey(String sourceDir, String fileName, byte[] encoded) throws IOException {
        store(sourceDir, fileName, KeyFormat.PEM, encoded, PUB_KEY_PREFIX, PUB_KEY_SUFFIX);
    }

    public static void storeDERCertificate(String sourceDir, String fileName, byte[] encoded) throws IOException {
        store(sourceDir, fileName, KeyFormat.DER, encoded, null, null);
    }

    public static void storeDERPrivateKey(String sourceDir, String fileName, byte[] encoded) throws IOException {
        store(sourceDir, fileName, KeyFormat.DER, encoded, null, null);
    }

    public static void storeDERPublicKey(String sourceDir, String fileName, byte[] encoded) throws IOException {
        store(sourceDir, fileName, KeyFormat.PEM, encoded, null, null);
    }

    public static void store(String sourceDir, String fileName, KeyFormat publicKeyFormat, byte[] encoded,
                           String prefix, String suffix) throws IOException {
        FileOutputStream keyFile = new FileOutputStream(new File(sourceDir, fileName));
        if (publicKeyFormat == KeyFormat.DER) {
            IOUtils.write(encoded, keyFile);
            return;
        }
        String content = String.format(WRAPPED_FORMAT, prefix, makePEM(encoded), suffix);
        IOUtils.write(content, keyFile, StandardCharsets.UTF_8);
        IOUtils.closeQuietly(keyFile);
    }

    public static String makePEM(byte[] content) {
        return Base64.getMimeEncoder(64, System.lineSeparator().getBytes(StandardCharsets.UTF_8))
                .encodeToString(content);
    }

    public static byte[] decodePEM(String encoded) {
        return Base64.getMimeDecoder().decode(encoded);
    }

    public static String makePrivatePEM(byte[] content) {
        return String.format(WRAPPED_FORMAT, PRIVATE_KEY_PREFIX, makePEM(content), PRIVATE_KEY_SUFFIX);
    }

    public static String makePublicPEM(byte[] content) {
        return String.format(WRAPPED_FORMAT, PUB_KEY_PREFIX, makePEM(content), PUB_KEY_SUFFIX);
    }

    public static Date daysFrom(Date startDate, int days) {
        MutableDateTime dateTime = new MutableDateTime(startDate);
        dateTime.addDays(days);
        return dateTime.toDate();
    }

    public static Date daysFromNow(int days) {
        MutableDateTime dateTime = new MutableDateTime();
        dateTime.addDays(days);
        return dateTime.toDate();
    }

    public static X500Name emptyAttrMap() {
        return createNameFromMap(EMPTY_NAME);
    }

    public static Map read(X509Certificate certificate) throws CertificateEncodingException, NoSuchAlgorithmException {
        Map<String, Object> certDetails = new HashMap<>();

        Map<CertAttr, String> subjectAttrs = parseX509Name(certificate.getSubjectDN().getName());
        Map<CertAttr, String> issuerAttrs = parseX509Name(certificate.getIssuerDN().getName());

        certDetails.put("subject_str", certificate.getSubjectDN().getName());
        certDetails.put("subject", subjectAttrs);
        certDetails.put("issuer_str", certificate.getIssuerX500Principal().getName());
        certDetails.put("issuer", issuerAttrs);

        //certDetails.put("content", makePEM(certificate.getEncoded()));
        Map<String, String> fingerPrints = new HashMap<>();
        byte[] sha1 = MessageDigest.getInstance("SHA-1").digest(certificate.getEncoded());
        byte[] sha256 = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        fingerPrints.put("SHA-1", toHex(sha1));
        fingerPrints.put("SHA-256", toHex(sha256));
        certDetails.put("fingerprint", fingerPrints);

        certDetails.put("valid_from", certificate.getNotBefore());
        certDetails.put("valid_till", certificate.getNotAfter());

        certDetails.put("signature_algo", certificate.getSigAlgName());
        certDetails.put("serial_number", certificate.getSerialNumber());
        certDetails.put("version", certificate.getVersion());

        return certDetails;
    }

    public static String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte aByte : bytes)
            result.append(String.format("%02X", aByte));

        return result.toString();
    }
}
