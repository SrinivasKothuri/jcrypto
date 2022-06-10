package org.jcrypto.pki;

import org.apache.commons.lang3.RandomUtils;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jcrypto.annotations.JCryptoAttr;
import org.jcrypto.util.JCryptoUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;

public class X509CertificateCreator extends CommonAttributes {

    private static final int DEFAULT_VALID_DAYS = 365;

    @JCryptoAttr(required = true)
    private PrivateKey fPrivateKey;
    @JCryptoAttr(required = true)
    private String fSigningAlgorithm;
    @JCryptoAttr
    private X500Name fIssuer;
    @JCryptoAttr
    private X500Name fSubject;
    @JCryptoAttr
    private Date fValidityStart;
    @JCryptoAttr
    private Date fValidityEnd;

    private X509CertificateCreator(String provider, SecureRandom secureRandom, PrivateKey privateKey,
                                   String signingAlgorithm, X500Name issuer, X500Name subject, Date validityStart,
                                   Date validityDuration) {
        super(provider, secureRandom);
        fPrivateKey = privateKey;
        fSigningAlgorithm = signingAlgorithm;
        fIssuer = issuer;
        fSubject = subject;
        fValidityStart = validityStart;
        fValidityEnd = validityDuration;
    }

    public X509Certificate create(PublicKey publicKey) throws OperatorCreationException, CertificateException {

        if (publicKey == null)
            throw new IllegalArgumentException("Public Key is not specified to create X509Certificate");

        byte[] encodedPublicKey = publicKey.getEncoded();

        X509v3CertificateBuilder v3CertBuild =
                new X509v3CertificateBuilder(fIssuer, new BigInteger(String.valueOf(RandomUtils.nextLong())),
                        defaultIfNull(fValidityStart, new Date()),
                        defaultIfNull(fValidityEnd, JCryptoUtil.daysFromNow(365)), fSubject,
                        SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(encodedPublicKey)));

        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(fSigningAlgorithm);
        if (fSecureRandom != null)
            jcaContentSignerBuilder.setSecureRandom(fSecureRandom);
        if (fProvider != null)
            jcaContentSignerBuilder.setProvider(fProvider);
        ContentSigner sigGen = jcaContentSignerBuilder.build(fPrivateKey);
        JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
        if (fProvider != null)
            jcaX509CertificateConverter.setProvider(fProvider);

        return jcaX509CertificateConverter.getCertificate(v3CertBuild.build(sigGen));
    }

    public void store(PublicKey publicKey, String targetDir, String fileName, JCryptoUtil.KeyFormat format)
            throws OperatorCreationException, CertificateException, IOException {
        X509Certificate certificate = create(publicKey);
        byte[] encoded = certificate.getEncoded();

        if (format == JCryptoUtil.KeyFormat.PEM)
            JCryptoUtil.storePEMCertificate(targetDir, fileName, encoded);
        else
            JCryptoUtil.storeDERCertificate(targetDir, fileName, encoded);
    }

    public static class Builder extends CommonAttributes.Builder {
        private PrivateKey fPrivateKey;
        private String fSigningAlgorithm;
        private X500Name fIssuer;
        private X500Name fSubject;
        private Date fValidityStart;
        private Date fValidityEnd;

        public Builder withSigningAlgorithm(String signingAlgorithm) {
            fSigningAlgorithm = signingAlgorithm;
            return this;
        }

        public Builder withPrivateKey(PrivateKey privateKey) {
            fPrivateKey = privateKey;
            return this;
        }

        public Builder withIssuer(Map<JCryptoUtil.CertAttr, String> issuerAttributes) {
            fIssuer = JCryptoUtil.createNameFromMap(issuerAttributes);
            return this;
        }

        public Builder withSubject(Map<JCryptoUtil.CertAttr, String> subjectAttributes) {
            fSubject = JCryptoUtil.createNameFromMap(subjectAttributes);
            return this;
        }

        public Builder withValidityStart(Date validityStart) {
            fValidityStart = validityStart;
            return this;
        }

        public Builder withValidityEnd(Date validityEnd) {
            fValidityEnd = validityEnd;
            return this;
        }

        public X509CertificateCreator build() {
            checkDefaults();
            return new X509CertificateCreator(fProvider, fSecureRandom, fPrivateKey, fSigningAlgorithm,
                    fIssuer, fSubject, fValidityStart, fValidityEnd);
        }

        @Override
        protected void checkDefaults() {
            if (fPrivateKey == null)
                throw new IllegalArgumentException("Private Key is not specified to create Certificate");
            if (fSigningAlgorithm == null)
                throw new IllegalArgumentException("Signing Algorithm is not specified to create Certificate");

            fValidityStart = defaultIfNull(fValidityStart, new Date());
            fValidityEnd = defaultIfNull(fValidityEnd, JCryptoUtil.daysFrom(fValidityStart, DEFAULT_VALID_DAYS));
            fSubject = defaultIfNull(fSubject, JCryptoUtil.emptyAttrMap());
            fIssuer = defaultIfNull(fIssuer, JCryptoUtil.emptyAttrMap());
        }
    }
}
