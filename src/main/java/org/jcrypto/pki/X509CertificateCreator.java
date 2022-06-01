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
import org.jcrypto.util.JCryptoUtil;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

public class X509CertificateCreator extends CommonAttributes {

    private String fKeyType;
    private String fSigningAlgorithm;
    private X500Name fIssuer;
    private X500Name fSubject;
    private Date fValidityStart;
    private Date fValidityEnd;
    private int fKeySize;

    private X509CertificateCreator(String provider, SecureRandom secureRandom, String keyType,
                                   String signingAlgorithm, X500Name issuer, X500Name subject, Date validityStart,
                                   Date validityDuration, int keySize) {
        super(provider, secureRandom);
        fKeyType = keyType;
        fSigningAlgorithm = signingAlgorithm;
        fIssuer = issuer;
        fSubject = subject;
        fValidityStart = validityStart;
        fValidityEnd = validityDuration;
        fKeySize = keySize;
    }

    public X509Certificate create() throws NoSuchAlgorithmException, NoSuchProviderException,
            OperatorCreationException, CertificateException {

        KeyPairCreator.Builder builder = new KeyPairCreator.Builder();
        KeyPair keyPair = builder.withKeySize(fKeySize).withAlgorithm(fKeyType).build().create();
        byte[] encodedPublicKey = keyPair.getPublic().getEncoded();

        X509v3CertificateBuilder v3CertBuild =
                new X509v3CertificateBuilder(fIssuer, new BigInteger(String.valueOf(RandomUtils.nextLong())),
                        fValidityStart, fValidityEnd, fSubject,
                        SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(encodedPublicKey)));

        ContentSigner sigGen = new JcaContentSignerBuilder(fSigningAlgorithm)
                /*.setProvider("BC")*/.build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()./*setProvider("BC").*/getCertificate(v3CertBuild.build(sigGen));
    }

    public static class Builder extends CommonAttributes.Builder {
        private String fKeyType;
        private int fKeySize = -1;
        private String fSigningAlgorithm;
        private X500Name fIssuer;
        private X500Name fSubject;
        private Date fValidityStart;
        private Date fValidityEnd;


        public Builder withKeyType(String keyType) {
            fKeyType = keyType;
            return this;
        }

        public Builder withSigningAlgorithm(String signingAlgorithm) {
            fSigningAlgorithm = signingAlgorithm;
            return this;
        }

        public Builder withKeySize(int keySize) {
            fKeySize = keySize;
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
            return new X509CertificateCreator(fProvider, fSecureRandom, fKeyType, fSigningAlgorithm,
                    fIssuer, fSubject, fValidityStart, fValidityEnd, fKeySize);
        }

        @Override
        protected void checkDefaults() {
            if (fKeyType == null)
                throw new IllegalArgumentException("KeyType is not specified to create Certificate");
            if (fSigningAlgorithm == null)
                throw new IllegalArgumentException("Signing Algorithm is not specified to create Certificate");
            if (fIssuer == null)
                throw new IllegalArgumentException("One or more X500Name are not specified to create Certificate");
        }
    }
}
